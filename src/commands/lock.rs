//! `hsh lock` — forget the cached secrets.

use anyhow::Result;

use crate::client;
use crate::protocol::Request;

pub fn run() -> Result<()> {
    client::request_ok(&Request::Lock)?;
    println!("agent: secrets forgotten");
    Ok(())
}
