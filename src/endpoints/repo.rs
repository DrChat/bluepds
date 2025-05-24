use std::{collections::HashSet, str::FromStr};

use anyhow::{anyhow, Context};
use atrium_api::{
    com::atproto::repo::{self, defs::CommitMetaData},
    types::{
        string::{AtIdentifier, Nsid, Tid},
        LimitedU32, Object, TryFromUnknown, TryIntoUnknown, Unknown,
    },
};
use atrium_repo::{blockstore::CarStore, Cid};
use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{self, StatusCode},
    routing::{get, post},
    Json, Router,
};
use constcat::concat;
use futures::TryStreamExt;
use metrics::counter;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::{
    auth::AuthenticatedUser,
    config::AppConfig,
    firehose::{self, FirehoseProducer, RepoOp},
    metrics::{REPO_COMMITS, REPO_OP_CREATE, REPO_OP_DELETE, REPO_OP_UPDATE},
    storage, AppState, Db, Error, Result, SigningKey,
};

/// IPLD CID raw binary
const IPLD_RAW: u64 = 0x55;
/// SHA2-256 mulithash
const IPLD_MH_SHA2_256: u64 = 0x12;

#[derive(Deserialize, Debug, Clone)]
struct BlobRef {
    #[serde(rename = "$link")]
    link: String,
}

async fn swap_commit(
    db: impl sqlx::Executor<'_, Database = sqlx::Sqlite>,
    cid: Cid,
    rev: Tid,
    old_cid: Option<Cid>,
    did_str: &str,
) -> anyhow::Result<bool> {
    let cid_str = cid.to_string();
    let rev_str = rev.to_string();

    if let Some(swap) = &old_cid {
        let swap_str = swap.to_string();

        let r = sqlx::query!(
            r#"UPDATE accounts SET root = ?, rev = ? WHERE did = ? AND root = ?"#,
            cid_str,
            rev_str,
            did_str,
            swap_str,
        )
        .execute(db)
        .await
        .context("failed to update root")?;

        // If the swap failed, indicate as such.
        Ok(r.rows_affected() != 0)
    } else {
        sqlx::query!(
            r#"UPDATE accounts SET root = ?, rev = ? WHERE did = ?"#,
            cid_str,
            rev_str,
            did_str,
        )
        .execute(db)
        .await
        .context("failed to update root")?;

        Ok(true)
    }
}

async fn resolve_did(
    db: &Db,
    ident: &AtIdentifier,
) -> anyhow::Result<(
    atrium_api::types::string::Did,
    atrium_api::types::string::Handle,
)> {
    let (handle, did) = match &ident {
        AtIdentifier::Handle(handle) => {
            let handle = handle.as_str();
            let did = sqlx::query_scalar!(r#"SELECT did FROM handles WHERE handle = ?"#, handle)
                .fetch_one(db)
                .await
                .context("failed to query did")?;

            (handle.to_string(), did)
        }
        AtIdentifier::Did(did) => {
            let did = did.as_str();
            let handle = sqlx::query_scalar!(r#"SELECT handle FROM handles WHERE did = ?"#, did)
                .fetch_one(db)
                .await
                .context("failed to query did")?;

            (handle, did.to_string())
        }
    };

    Ok((
        atrium_api::types::string::Did::new(did).unwrap(),
        atrium_api::types::string::Handle::new(handle).unwrap(),
    ))
}

fn scan_blobs(o: &Unknown) -> anyhow::Result<Vec<Cid>> {
    // { "$type": "blob", "ref": { "$link": "bafyrei..." } }
    let v = serde_json::Value::try_from_unknown(o.clone())
        .context("failed to convert unknown into json")?;

    let mut cids = Vec::new();
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            serde_json::Value::Null => (),
            serde_json::Value::Bool(_) => (),
            serde_json::Value::Number(_) => (),
            serde_json::Value::String(_) => (),
            serde_json::Value::Array(values) => stack.extend(values.into_iter()),
            serde_json::Value::Object(map) => {
                let (ty, rf) = (map.get("$type"), map.get("ref"));

                if let (Some(ty), Some(rf)) = (ty, rf) {
                    if ty == &serde_json::Value::String("blob".to_string()) {
                        if let Ok(rf) = serde_json::from_value::<BlobRef>(rf.clone()) {
                            cids.push(Cid::from_str(&rf.link).context("failed to convert cid")?);
                        }
                    }
                }

                stack.extend(map.values().cloned());
            }
        }
    }

    Ok(cids)
}

#[test]
fn test_scan_blobs() {
    use std::str::FromStr;

    let json = serde_json::json!({
        "test": "a",
        "blob": {
            "$type": "blob",
            "ref": {
                "$link": "bafkreifzxf2wa6dyakzbdaxkz2wkvfrv3hiuafhxewbn5wahcw6eh3hzji"
            }
        }
    });

    let b = scan_blobs(&json.try_into_unknown().unwrap()).unwrap();
    assert_eq!(
        b,
        vec![Cid::from_str("bafkreifzxf2wa6dyakzbdaxkz2wkvfrv3hiuafhxewbn5wahcw6eh3hzji").unwrap()]
    );
}

async fn apply_writes(
    user: AuthenticatedUser,
    State(skey): State<SigningKey>,
    State(config): State<AppConfig>,
    State(db): State<Db>,
    State(fhp): State<FirehoseProducer>,
    Json(input): Json<repo::apply_writes::Input>,
) -> Result<Json<repo::apply_writes::Output>> {
    use atrium_api::com::atproto::repo::apply_writes::{self, InputWritesItem, OutputResultsItem};

    // TODO: `input.validate`

    let (target_did, _) = resolve_did(&db, &input.repo)
        .await
        .context("failed to resolve did")?;

    // Ensure that we are updating the correct repository.
    if target_did.as_str() != user.did() {
        return Err(Error::with_status(
            StatusCode::BAD_REQUEST,
            anyhow!("repo did not match the authenticated user"),
        ));
    }

    let mut repo = storage::open_repo_db(&config.repo, &db, user.did())
        .await
        .context("failed to open user repo")?;
    let orig_cid = repo.root();
    let orig_rev = repo.commit().rev();

    let mut blobs = vec![];
    let mut res = vec![];
    let mut ops = vec![];
    let mut keys = vec![];
    for write in &input.writes {
        let (builder, key) = match write {
            InputWritesItem::Create(object) => {
                let key = format!(
                    "{}/{}",
                    object.collection.as_str(),
                    object
                        .rkey
                        .as_deref()
                        .unwrap_or(Tid::now(LimitedU32::MIN).as_str())
                );
                let uri = format!("at://{}/{}", user.did(), key);

                let (b, c) = repo
                    .add_raw(&key, &object.value)
                    .await
                    .context("failed to add record")?;

                if let Ok(new_blobs) = scan_blobs(&object.value) {
                    blobs.extend(new_blobs.into_iter().map(|b| (key.to_string(), b)));
                }

                ops.push(RepoOp::Create {
                    cid: c,
                    path: key.clone(),
                });

                res.push(OutputResultsItem::CreateResult(Box::new(
                    apply_writes::CreateResultData {
                        cid: atrium_api::types::string::Cid::new(c),
                        uri,
                        validation_status: None,
                    }
                    .into(),
                )));

                (b, key)
            }
            InputWritesItem::Update(object) => {
                let key = format!("{}/{}", object.collection.as_str(), object.rkey.as_str());
                let uri = format!("at://{}/{}", user.did(), key);

                let prev = repo
                    .tree()
                    .get(&key)
                    .await
                    .context("failed to search MST")?
                    .context("previous record does not exist")?;

                let (b, c) = repo
                    .update_raw(&key, &object.value)
                    .await
                    .context("failed to add record")?;

                if let Ok(new_blobs) = scan_blobs(&object.value) {
                    blobs.extend(new_blobs.into_iter().map(|b| (key.to_string(), b)));
                }

                ops.push(RepoOp::Update {
                    cid: c,
                    path: key.clone(),
                    prev,
                });

                res.push(OutputResultsItem::UpdateResult(Box::new(
                    apply_writes::UpdateResultData {
                        cid: atrium_api::types::string::Cid::new(c),
                        uri,
                        validation_status: None,
                    }
                    .into(),
                )));

                (b, key)
            }
            InputWritesItem::Delete(object) => {
                let key = format!("{}/{}", object.collection.as_str(), object.rkey.as_str());

                let prev = repo
                    .tree()
                    .get(&key)
                    .await
                    .context("failed to search MST")?
                    .context("previous record does not exist")?;

                ops.push(RepoOp::Delete {
                    path: key.clone(),
                    prev,
                });

                res.push(OutputResultsItem::DeleteResult(Box::new(
                    apply_writes::DeleteResultData {}.into(),
                )));

                let b = repo
                    .delete_raw(&key)
                    .await
                    .context("failed to add record")?;

                (b, key)
            }
        };

        let sig = skey
            .sign(&builder.bytes())
            .context("failed to sign commit")?;

        builder
            .finalize(sig)
            .await
            .context("failed to write signed commit")?;

        keys.push(key);
    }

    // Construct a firehose record.
    let mut mem = Vec::new();
    let mut store = CarStore::create_with_roots(std::io::Cursor::new(&mut mem), [repo.root()])
        .await
        .context("failed to create temp store")?;

    // Extract the records out of the user's repository.
    for key in keys {
        repo.extract_raw_into(&key, &mut store)
            .await
            .context("failed to extract key")?;
    }

    let mut tx = db.begin().await.context("failed to begin transaction")?;

    if !swap_commit(
        &mut *tx,
        repo.root(),
        repo.commit().rev(),
        input.swap_commit.as_ref().map(|c| c.as_ref().clone()),
        &user.did(),
    )
    .await
    .context("failed to swap commit")?
    {
        // This should always succeed.
        let old = input.swap_commit.clone().unwrap();

        // The swap failed. Return the old commit and do not update the repository.
        return Ok(Json(
            repo::apply_writes::OutputData {
                results: None,
                commit: Some(
                    CommitMetaData {
                        cid: old.clone(),
                        rev: orig_rev,
                    }
                    .into(),
                ),
            }
            .into(),
        ));
    }

    let did_str = user.did();

    // For updates and removals, unlink the old/deleted record from the blob_ref table.
    for op in &ops {
        match op {
            RepoOp::Update { path, .. } | RepoOp::Delete { path, .. } => {
                // FIXME: This may cause issues if a user deletes more than one record referencing the same blob.
                sqlx::query!(
                    r#"UPDATE blob_ref SET record = NULL WHERE did = ? AND record = ?"#,
                    did_str,
                    path
                )
                .execute(&mut *tx)
                .await
                .context("failed to remove blob_ref")?;
            }
            _ => {}
        }
    }

    for (key, cid) in &blobs {
        let cid_str = cid.to_string();
        let r = sqlx::query!(
            r#"UPDATE blob_ref SET record = ? WHERE cid = ? AND did = ? AND record IS NULL"#,
            key,
            cid_str,
            did_str,
        )
        .execute(&mut *tx)
        .await
        .context("failed to update blob_ref")?;

        // Handle the case where a new record references an existing blob.
        if r.rows_affected() == 0 {
            sqlx::query!(
                r#"INSERT INTO blob_ref (record, cid, did) VALUES (?, ?, ?)"#,
                key,
                cid_str,
                did_str,
            )
            .execute(&mut *tx)
            .await
            .context("failed to update blob_ref")?;
        }
    }

    tx.commit()
        .await
        .context("failed to commit blob ref to database")?;

    // Update counters.
    counter!(REPO_COMMITS).increment(1);
    for op in &ops {
        match op {
            RepoOp::Create { .. } => counter!(REPO_OP_CREATE).increment(1),
            RepoOp::Update { .. } => counter!(REPO_OP_UPDATE).increment(1),
            RepoOp::Delete { .. } => counter!(REPO_OP_DELETE).increment(1),
        }
    }

    // We've committed the transaction to the database, and the commit is now stored in the user's
    // canonical repository.
    // We can now broadcast this on the firehose.
    fhp.commit(firehose::Commit {
        car: mem,
        ops: ops,
        cid: repo.root(),
        rev: repo.commit().rev().to_string(),
        did: atrium_api::types::string::Did::new(user.did()).unwrap(),
        pcid: Some(orig_cid),
        blobs: blobs.into_iter().map(|(_, c)| c).collect::<Vec<_>>(),
    })
    .await;

    Ok(Json(
        repo::apply_writes::OutputData {
            results: Some(res),
            commit: Some(
                CommitMetaData {
                    cid: atrium_api::types::string::Cid::new(repo.root()),
                    rev: repo.commit().rev(),
                }
                .into(),
            ),
        }
        .into(),
    ))
}

async fn create_record(
    user: AuthenticatedUser,
    State(skey): State<SigningKey>,
    State(config): State<AppConfig>,
    State(db): State<Db>,
    State(fhp): State<FirehoseProducer>,
    Json(input): Json<repo::create_record::Input>,
) -> Result<Json<repo::create_record::Output>> {
    let input = (*input).clone();
    let input = repo::apply_writes::InputData {
        repo: input.repo,
        validate: input.validate,
        swap_commit: input.swap_commit,
        writes: vec![repo::apply_writes::InputWritesItem::Create(Box::new(
            repo::apply_writes::CreateData {
                collection: input.collection,
                rkey: input.rkey,
                value: input.record,
            }
            .into(),
        ))],
    }
    .into();

    let r = apply_writes(
        user,
        State(skey),
        State(config),
        State(db),
        State(fhp),
        Json(input),
    )
    .await
    .context("failed to apply writes")?;
    let r = (**r).clone();

    let res = r
        .results
        .and_then(|r| r.get(0).cloned())
        .context("unexpected output from apply_writes")?;
    let res = if let repo::apply_writes::OutputResultsItem::CreateResult(c) = res {
        Some(c)
    } else {
        None
    };
    let res = res.context("unexpected result from apply_writes")?;

    Ok(Json(
        repo::create_record::OutputData {
            cid: res.cid.clone(),
            commit: r.commit.clone(),
            uri: res.uri.clone(),
            validation_status: Some("unknown".to_string()),
        }
        .into(),
    ))
}

async fn put_record(
    user: AuthenticatedUser,
    State(skey): State<SigningKey>,
    State(config): State<AppConfig>,
    State(db): State<Db>,
    State(fhp): State<FirehoseProducer>,
    Json(input): Json<repo::put_record::Input>,
) -> Result<Json<repo::put_record::Output>> {
    // TODO: `input.swap_record`

    // FIXME: "put" implies that we will create the record if it does not exist.
    // We currently only update existing records and/or throw an error if one doesn't exist.
    let input = (*input).clone();
    let input = repo::apply_writes::InputData {
        repo: input.repo,
        validate: input.validate,
        swap_commit: input.swap_commit,
        writes: vec![repo::apply_writes::InputWritesItem::Update(Box::new(
            repo::apply_writes::UpdateData {
                collection: input.collection,
                rkey: input.rkey,
                value: input.record,
            }
            .into(),
        ))],
    }
    .into();

    let r = apply_writes(
        user,
        State(skey),
        State(config),
        State(db),
        State(fhp),
        Json(input),
    )
    .await
    .context("failed to apply writes")?;
    let r = (**r).clone();

    let res = r
        .results
        .and_then(|r| r.get(0).cloned())
        .context("unexpected output from apply_writes")?;
    let res = if let repo::apply_writes::OutputResultsItem::UpdateResult(c) = res {
        Some(c)
    } else {
        None
    };
    let res = res.context("unexpected result from apply_writes")?;

    Ok(Json(
        repo::put_record::OutputData {
            cid: res.cid.clone(),
            commit: r.commit,
            uri: res.uri.clone(),
            validation_status: Some("unknown".to_string()),
        }
        .into(),
    ))
}

async fn delete_record(
    user: AuthenticatedUser,
    State(skey): State<SigningKey>,
    State(config): State<AppConfig>,
    State(db): State<Db>,
    State(fhp): State<FirehoseProducer>,
    Json(input): Json<repo::delete_record::Input>,
) -> Result<Json<repo::delete_record::Output>> {
    // TODO: `input.swap_record`

    let input = (*input).clone();
    let input = repo::apply_writes::InputData {
        repo: input.repo,
        swap_commit: input.swap_commit,
        validate: None,
        writes: vec![repo::apply_writes::InputWritesItem::Delete(Box::new(
            repo::apply_writes::DeleteData {
                collection: input.collection,
                rkey: input.rkey,
            }
            .into(),
        ))],
    }
    .into();

    let r = apply_writes(
        user,
        State(skey),
        State(config),
        State(db),
        State(fhp),
        Json(input),
    )
    .await
    .context("failed to apply writes")?;
    let r = (**r).clone();

    Ok(Json(
        repo::delete_record::OutputData { commit: r.commit }.into(),
    ))
}

async fn describe_repo(
    State(config): State<AppConfig>,
    State(db): State<Db>,
    Query(input): Query<repo::describe_repo::ParametersData>,
) -> Result<Json<repo::describe_repo::Output>> {
    // Lookup the DID by the provided handle.
    let (did, handle) = resolve_did(&db, &input.repo)
        .await
        .context("failed to resolve handle")?;

    let mut repo = storage::open_repo_db(&config.repo, &db, did.as_str())
        .await
        .context("failed to open user repo")?;

    let mut collections = HashSet::new();

    let mut tree = repo.tree();
    let mut it = Box::pin(tree.keys());
    while let Some(key) = it.try_next().await.context("failed to iterate repo keys")? {
        if let Some((collection, _rkey)) = key.split_once('/') {
            collections.insert(collection.to_string());
        }
    }

    Ok(Json(
        repo::describe_repo::OutputData {
            collections: collections
                .into_iter()
                .map(|s| Nsid::new(s).unwrap())
                .collect::<Vec<_>>(),
            did: did.clone(),
            did_doc: Unknown::Null, // TODO: Fetch the DID document from the PLC directory
            handle: handle.clone(),
            handle_is_correct: true, // TODO
        }
        .into(),
    ))
}

async fn get_record(
    State(config): State<AppConfig>,
    State(db): State<Db>,
    Query(input): Query<repo::get_record::ParametersData>,
) -> Result<Json<repo::get_record::Output>> {
    if input.cid.is_some() {
        return Err(Error::unimplemented(anyhow!(
            "looking up old records is unsupported"
        )));
    }

    // Lookup the DID by the provided handle.
    let (did, _handle) = resolve_did(&db, &input.repo)
        .await
        .context("failed to resolve handle")?;

    let mut repo = storage::open_repo_db(&config.repo, &db, did.as_str())
        .await
        .context("failed to open user repo")?;

    let key = format!("{}/{}", input.collection.as_str(), input.rkey.as_str());
    let uri = format!("at://{}/{}", did.as_str(), &key);

    let cid = repo
        .tree()
        .get(&key)
        .await
        .context("failed to find record")?;

    let record: Option<serde_json::Value> =
        repo.get_raw(&key).await.context("failed to read record")?;

    if let Some(record) = record {
        Ok(Json(
            repo::get_record::OutputData {
                cid: cid.map(atrium_api::types::string::Cid::new),
                uri,
                value: record.try_into_unknown().unwrap(),
            }
            .into(),
        ))
    } else {
        return Err(Error::with_status(
            StatusCode::NOT_FOUND,
            anyhow!("could not find record {uri}"),
        ));
    }
}

async fn list_records(
    State(config): State<AppConfig>,
    State(db): State<Db>,
    Query(input): Query<Object<repo::list_records::ParametersData>>,
) -> Result<Json<repo::list_records::Output>> {
    // TODO: `input.reverse`

    // Lookup the DID by the provided handle.
    let (did, _handle) = resolve_did(&db, &input.repo)
        .await
        .context("failed to resolve handle")?;

    let mut repo = storage::open_repo_db(&config.repo, &db, did.as_str())
        .await
        .context("failed to open user repo")?;

    let mut keys = Vec::new();
    let mut tree = repo.tree();

    let mut it = Box::pin(tree.entries_prefixed(input.collection.as_str()));
    while let Some((key, cid)) = it.try_next().await.context("failed to iterate keys")? {
        keys.push((key, cid));
    }

    drop(it);

    // TODO: Calculate the view on `keys` using `cursor` and `limit`.

    let mut records = Vec::new();
    for (key, cid) in &keys {
        let value: serde_json::Value = repo
            .get_raw(key)
            .await
            .context("failed to get record")?
            .context("record not found")?;

        records.push(
            repo::list_records::RecordData {
                cid: atrium_api::types::string::Cid::new(*cid),
                uri: format!("at://{}/{}", did.as_str(), key),
                value: value.try_into_unknown().unwrap(),
            }
            .into(),
        )
    }

    Ok(Json(
        repo::list_records::OutputData {
            cursor: keys.last().map(|(k, _)| k.clone()),
            records,
        }
        .into(),
    ))
}

async fn upload_blob(
    user: AuthenticatedUser,
    State(config): State<AppConfig>,
    State(db): State<Db>,
    request: Request<Body>,
) -> Result<Json<repo::upload_blob::Output>> {
    let length = request
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .context("no content length provided")?
        .to_str()
        .map_err(anyhow::Error::from)
        .and_then(|s| u64::from_str_radix(s, 10).map_err(anyhow::Error::from))
        .context("invalid content-length header")?;
    let mime = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .context("no content-type provided")?
        .to_str()
        .context("invalid content-type provided")?
        .to_string();

    if length > config.blob.limit {
        return Err(Error::with_status(
            StatusCode::PAYLOAD_TOO_LARGE,
            anyhow!("size {} above limit {}", length, config.blob.limit),
        ));
    }

    // FIXME: Need to make this more robust. This will fail under load.
    let filename = config
        .blob
        .path
        .join(format!("temp-{}.blob", chrono::Utc::now().timestamp()));
    let mut file = tokio::fs::File::create(&filename)
        .await
        .context("failed to create temporary file")?;

    let mut len = 0usize;
    let mut sha = Sha256::new();
    let mut stream = request.into_body().into_data_stream();
    while let Some(bytes) = stream.try_next().await.context("failed to receive file")? {
        len += bytes.len();

        // Deal with any sneaky end-users trying to bypass size limitations.
        if len as u64 > config.blob.limit {
            drop(file);
            tokio::fs::remove_file(&filename)
                .await
                .context("failed to remove temp file")?;

            return Err(Error::with_status(
                StatusCode::PAYLOAD_TOO_LARGE,
                anyhow!("size above limit and content-length header was wrong"),
            ));
        }

        sha.update(&bytes);

        file.write_all(&bytes)
            .await
            .context("failed to write blob")?;
    }

    drop(file);
    let hash = sha.finalize();

    let cid = atrium_repo::Cid::new_v1(
        IPLD_RAW,
        atrium_repo::Multihash::wrap(IPLD_MH_SHA2_256, hash.as_slice()).unwrap(),
    );

    let cid_str = cid.to_string();

    tokio::fs::rename(
        &filename,
        config.blob.path.join(format!("{}.blob", cid_str)),
    )
    .await
    .context("failed to finalize blob")?;

    let did_str = user.did();

    sqlx::query!(
        r#"INSERT INTO blob_ref (cid, did, record) VALUES (?, ?, NULL)"#,
        cid_str,
        did_str
    )
    .execute(&db)
    .await
    .context("failed to insert blob into database")?;

    Ok(Json(
        repo::upload_blob::OutputData {
            blob: atrium_api::types::BlobRef::Typed(atrium_api::types::TypedBlobRef::Blob(
                atrium_api::types::Blob {
                    r#ref: atrium_api::types::CidLink(cid),
                    mime_type: mime,
                    size: len,
                },
            )),
        }
        .into(),
    ))
}

#[rustfmt::skip]
pub fn routes() -> Router<AppState> {
    // AP /xrpc/com.atproto.repo.applyWrites
    // AP /xrpc/com.atproto.repo.createRecord
    // AP /xrpc/com.atproto.repo.putRecord
    // AP /xrpc/com.atproto.repo.deleteRecord
    // AP /xrpc/com.atproto.repo.uploadBlob
    // UG /xrpc/com.atproto.repo.describeRepo
    // UG /xrpc/com.atproto.repo.getRecord
    // UG /xrpc/com.atproto.repo.listRecords
    Router::new()
        .route(concat!("/", repo::apply_writes::NSID),  post(apply_writes))
        .route(concat!("/", repo::create_record::NSID), post(create_record))
        .route(concat!("/", repo::put_record::NSID),    post(put_record))
        .route(concat!("/", repo::delete_record::NSID), post(delete_record))
        .route(concat!("/", repo::upload_blob::NSID),   post(upload_blob))
        .route(concat!("/", repo::describe_repo::NSID), get(describe_repo))
        .route(concat!("/", repo::get_record::NSID),    get(get_record))
        .route(concat!("/", repo::list_records::NSID),  get(list_records))
}
