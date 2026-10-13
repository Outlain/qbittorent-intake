//! Durable state, bounded torrent decoding, and portable encrypted backups.
//!
//! The modules intentionally know nothing about HTTP or qBittorrent. Their job is
//! to preserve facts and reject unsafe inputs before the workflow can use them.
pub mod backup;
pub mod db;
pub mod metainfo;
pub mod paths;
pub mod restore;
mod schema;
pub mod state;
pub mod storage;
pub use db::Database;
pub use metainfo::{parse_torrent, TorrentMetainfo};
pub use state::ControllerLock;
