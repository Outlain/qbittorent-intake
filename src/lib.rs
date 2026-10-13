//! Torrent Intake keeps downloaded content in staging until every file has a
//! complete, acceptable scan. Modules follow that data flow; start with `workflow`.
pub mod config;
pub mod http;
pub mod persistence;
pub mod scanning;
pub mod workflow;
