use std::{collections::VecDeque, time::Duration};

use anyhow::{bail, Result};
use atrium_api::{
    com::atproto::sync::{self},
    types::string::{Datetime, Did},
};
use atrium_repo::Cid;
use axum::extract::ws::{Message, WebSocket};
use rand::Rng;
use serde::{ser::SerializeMap, Serialize};
use tracing::{debug, error, info, warn};

use crate::{config::AppConfig, Client};

enum FirehoseMessage {
    Broadcast(sync::subscribe_repos::Message),
    Connect((axum::extract::ws::WebSocket, Option<i64>)),
}

enum FrameHeader {
    Message(String),
    Error,
}

impl Serialize for FrameHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        match self {
            FrameHeader::Message(s) => {
                map.serialize_key("op")?;
                map.serialize_value(&1)?;
                map.serialize_key("t")?;
                map.serialize_value(s.as_str())?;
            }
            FrameHeader::Error => {
                map.serialize_key("op")?;
                map.serialize_value(&-1)?;
            }
        }

        map.end()
    }
}

pub enum RepoOp {
    Create { cid: Cid, path: String },
    Update { cid: Cid, path: String, prev: Cid },
    Delete { path: String, prev: Cid },
}

impl Into<sync::subscribe_repos::RepoOp> for RepoOp {
    fn into(self) -> sync::subscribe_repos::RepoOp {
        let (action, cid, path) = match self {
            RepoOp::Create { cid, path } => ("create", Some(cid), path),
            RepoOp::Update { cid, path, prev: _prev } => ("update", Some(cid), path),
            RepoOp::Delete { path, prev: _prev } => ("delete", None, path),
        };

        sync::subscribe_repos::RepoOpData {
            action: action.to_string(),
            cid: cid.map(atrium_api::types::CidLink),
            path,
        }
        .into()
    }
}

pub struct Commit {
    /// The car file containing the commit blocks.
    pub car: Vec<u8>,
    /// The operations performed in this commit.
    pub ops: Vec<RepoOp>,
    /// The CID of the commit.
    pub cid: Cid,
    /// The revision of the commit.
    pub rev: String,
    /// The DID of the repository changed.
    pub did: Did,
    /// Blobs that were created in this commit.
    pub blobs: Vec<Cid>,
}

impl Into<sync::subscribe_repos::Commit> for Commit {
    fn into(self) -> sync::subscribe_repos::Commit {
        sync::subscribe_repos::CommitData {
            blobs: self
                .blobs
                .into_iter()
                .map(|b| atrium_api::types::CidLink(b))
                .collect::<Vec<_>>(),
            blocks: self.car,
            commit: atrium_api::types::CidLink(self.cid),
            ops: self.ops.into_iter().map(Into::into).collect::<Vec<_>>(),
            prev: None,
            rebase: false,
            repo: self.did,
            rev: self.rev,
            seq: 0,
            since: None,
            time: Datetime::now(),
            too_big: false,
        }
        .into()
    }
}

#[derive(Clone, Debug)]
pub struct FirehoseProducer {
    tx: tokio::sync::mpsc::Sender<FirehoseMessage>,
}

impl FirehoseProducer {
    /// Broadcast an `#account` event.
    pub async fn account(&self, account: impl Into<sync::subscribe_repos::Account>) {
        let _ = self
            .tx
            .send(FirehoseMessage::Broadcast(
                sync::subscribe_repos::Message::Account(Box::new(account.into())),
            ))
            .await;
    }

    /// Broadcast an `#identity` event.
    pub async fn identity(&self, identity: impl Into<sync::subscribe_repos::Identity>) {
        let _ = self
            .tx
            .send(FirehoseMessage::Broadcast(
                sync::subscribe_repos::Message::Identity(Box::new(identity.into())),
            ))
            .await;
    }

    /// Broadcast a `#commit` event.
    pub async fn commit(&self, commit: impl Into<sync::subscribe_repos::Commit>) {
        let _ = self
            .tx
            .send(FirehoseMessage::Broadcast(
                sync::subscribe_repos::Message::Commit(Box::new(commit.into())),
            ))
            .await;
    }

    pub async fn client_connection(&self, ws: WebSocket, cursor: Option<i64>) {
        let _ = self.tx.send(FirehoseMessage::Connect((ws, cursor))).await;
    }
}

async fn broadcast_message(
    clients: &mut Vec<WebSocket>,
    history: &mut VecDeque<(i64, &str, sync::subscribe_repos::Message)>,
    seq: &mut i64,
    mut msg: sync::subscribe_repos::Message,
) -> Result<()> {
    let enc = serde_ipld_dagcbor::to_vec(&msg).unwrap().into_boxed_slice();

    let mut dummy_seq = 0i64;
    let (ty, nseq) = match &mut msg {
        sync::subscribe_repos::Message::Account(m) => ("#account", &mut m.seq),
        sync::subscribe_repos::Message::Commit(m) => ("#commit", &mut m.seq),
        sync::subscribe_repos::Message::Handle(m) => ("#handle", &mut m.seq),
        sync::subscribe_repos::Message::Identity(m) => ("#identity", &mut m.seq),
        sync::subscribe_repos::Message::Info(_m) => ("#info", &mut dummy_seq),
        sync::subscribe_repos::Message::Migrate(m) => ("#migrate", &mut m.seq),
        sync::subscribe_repos::Message::Tombstone(m) => ("#tombstone", &mut m.seq),
    };

    info!(
        "Broadcasting message {} {} ({} bytes) to {} clients",
        *seq,
        ty,
        enc.len(),
        clients.len()
    );

    // Increment the sequence number.
    *nseq = *seq;

    history.push_back((*seq, ty, msg.clone()));
    *seq = seq.wrapping_add(1);

    let hdr = FrameHeader::Message(ty.to_string());

    let mut frame = Vec::new();
    serde_ipld_dagcbor::to_writer(&mut frame, &hdr).unwrap();
    serde_ipld_dagcbor::to_writer(&mut frame, &msg).unwrap();

    for i in (0..clients.len()).rev() {
        let client = &mut clients[i];
        if let Err(e) = client.send(Message::binary(frame.clone())).await {
            debug!("Firehose client disconnected: {e}");
            clients.remove(i);
        }
    }

    Ok(())
}

async fn broadcast_ping(clients: &mut Vec<WebSocket>) -> Result<()> {
    let contents = rand::thread_rng()
        .sample_iter(rand::distributions::Alphanumeric)
        .take(15)
        .map(char::from)
        .collect::<String>();

    // Send a websocket ping message.
    // Reference: https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#pings_and_pongs_the_heartbeat_of_websockets
    let message = Message::Ping(axum::body::Bytes::from_owner(contents));

    for i in (0..clients.len()).rev() {
        let client = &mut clients[i];
        if let Err(e) = client.send(message.clone()).await {
            debug!("Firehose client disconnected: {e}");
            clients.remove(i);
        }
    }

    Ok(())
}

async fn handle_connect(
    mut ws: WebSocket,
    seq: i64,
    history: &VecDeque<(i64, &str, sync::subscribe_repos::Message)>,
    cursor: Option<i64>,
) -> anyhow::Result<WebSocket> {
    if let Some(cursor) = cursor {
        let mut frame = Vec::new();

        // Cursor specified; attempt to backfill the consumer.
        if cursor > seq {
            let hdr = FrameHeader::Error;
            let msg = sync::subscribe_repos::Error::FutureCursor(Some(format!(
                "cursor {cursor} is greater than the current sequence number {seq}"
            )));

            serde_ipld_dagcbor::to_writer(&mut frame, &hdr).unwrap();
            serde_ipld_dagcbor::to_writer(&mut frame, &msg).unwrap();

            // Drop the connection.
            let _ = ws.send(Message::binary(frame)).await;
            bail!("connection dropped: cursor {cursor} is greater than the current sequence number {seq}");
        }

        let mut it = history.iter();
        while let Some((seq, ty, msg)) = it.next() {
            if *seq > cursor {
                break;
            }

            let hdr = FrameHeader::Message(ty.to_string());
            serde_ipld_dagcbor::to_writer(&mut frame, &hdr).unwrap();
            serde_ipld_dagcbor::to_writer(&mut frame, msg).unwrap();

            if let Err(e) = ws.send(Message::binary(frame.clone())).await {
                debug!("Firehose client disconnected during backfill: {e}");
                break;
            }

            // Clear out the frame to begin a new one.
            frame.clear();
        }
    }

    Ok(ws)
}

pub async fn reconnect_relays(client: &Client, config: &AppConfig) {
    // Avoid connecting to upstream relays in test mode.
    if config.test {
        return;
    }

    for relay in &config.firehose.relays {
        let host = match relay.host_str() {
            Some(host) => host,
            None => {
                warn!("relay {} has no host specified", relay);
                continue;
            }
        };

        let r = client
            .post(format!("https://{host}/xrpc/com.atproto.sync.requestCrawl"))
            .json(&serde_json::json!({
                "hostname": format!("https://{}", config.host_name)
            }))
            .send()
            .await;

        let r = match r {
            Ok(r) => r,
            Err(e) => {
                error!("failed to hit upstream relay {host}: {e}");
                continue;
            }
        };

        let s = r.status();
        if let Err(e) = r.error_for_status_ref() {
            error!("failed to hit upstream relay {host}: {e}");
        }

        let b = r.json::<serde_json::Value>().await;
        if let Ok(b) = b {
            info!("relay {host}: {} {}", s, b);
        } else {
            info!("relay {host}: {}", s);
        }
    }
}

/// The main entrypoint for the firehose.
///
/// This will broadcast all updates in this PDS out to anyone who is listening.
///
/// Reference: https://atproto.com/specs/sync
pub async fn spawn(
    client: Client,
    config: AppConfig,
) -> (tokio::task::JoinHandle<()>, FirehoseProducer) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1000);
    let handle = tokio::spawn(async move {
        let mut clients: Vec<WebSocket> = Vec::new();
        let mut history = VecDeque::with_capacity(1000);
        let mut seq = 1i64;

        // TODO: We should use `com.atproto.sync.notifyOfUpdate` to reach out to relays
        // that may have disconnected from us due to timeout.

        loop {
            match tokio::time::timeout(Duration::from_secs(30), rx.recv()).await {
                Ok(msg) => match msg {
                    Some(FirehoseMessage::Broadcast(msg)) => {
                        let _ = broadcast_message(&mut clients, &mut history, &mut seq, msg).await;
                    }
                    Some(FirehoseMessage::Connect((ws, cursor))) => {
                        match handle_connect(ws, seq, &mut history, cursor).await {
                            Ok(r) => {
                                clients.push(r);
                            }
                            Err(e) => {
                                error!("failed to connect new client: {e}");
                            }
                        }
                    }
                    // All producers have been destroyed.
                    None => break,
                },
                Err(_) => {
                    if clients.is_empty() {
                        warn!("no downstream relays connected to firehose; reconnecting");
                        reconnect_relays(&client, &config).await;
                    }

                    let _ = broadcast_ping(&mut clients).await;
                }
            }
        }
    });

    (handle, FirehoseProducer { tx })
}
