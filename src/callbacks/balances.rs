use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use clap::{Arg, ArgMatches, Command};

use crate::blockchain::proto::tx::TxOutpoint;
use crate::blockchain::proto::script::ScriptPattern;
use crate::blockchain::proto::ToRaw;

use crate::blockchain::proto::block::Block;
use crate::callbacks::{Callback, common};
use crate::common::Result;
use crate::common::utils;

/// Holds statistics for a single address
#[derive(Default)]
struct AddressStats {
    balance: u64,
    total_sent: u64,
    total_received: u64,
    first_spent_time: Option<u32>,
    last_spent_time: Option<u32>,
    first_received_time: Option<u32>,
    last_received_time: Option<u32>,
    pubkey: Option<String>,
}

/// Dumps all addresses with their balance information in a csv file
pub struct Balances {
    dump_folder: PathBuf,
    writer: BufWriter<File>,

    // key: txid + index
    unspents: HashMap<Vec<u8>, common::UnspentValue>,

    stats: HashMap<String, AddressStats>,

    keep_zero_balances: bool,

    start_height: u64,
    end_height: u64,
}

impl Balances {
    fn create_writer(cap: usize, path: PathBuf) -> Result<BufWriter<File>> {
        Ok(BufWriter::with_capacity(cap, File::create(path)?))
    }
}

impl Callback for Balances {
    fn build_subcommand() -> Command
    where
        Self: Sized,
    {
        Command::new("balances")
            .about("Dumps all addresses with non-zero balance to CSV file")
            .version("0.1")
            .author("gcarq <egger.m@protonmail.com>")
            .arg(
                Arg::new("dump-folder")
                    .help("Folder to store csv file")
                    .index(1)
                    .required(true),
            )
            .arg(
                Arg::new("keep-zero-balances")
                    .long("keep-zero-balances")
                    .action(clap::ArgAction::SetTrue)
                    .help("Keep addresses with zero balance in output"),
            )
    }

    fn new(matches: &ArgMatches) -> Result<Self>
    where
        Self: Sized,
    {
        let dump_folder = &PathBuf::from(matches.get_one::<String>("dump-folder").unwrap());
        let keep_zero = matches.get_flag("keep-zero-balances");
        let cb = Balances {
            dump_folder: PathBuf::from(dump_folder),
            writer: Balances::create_writer(4000000, dump_folder.join("balances.csv.tmp"))?,
            unspents: HashMap::with_capacity(10000000),
            stats: HashMap::new(),
            keep_zero_balances: keep_zero,
            start_height: 0,
            end_height: 0,
        };
        Ok(cb)
    }

    fn on_start(&mut self, block_height: u64) -> Result<()> {
        self.start_height = block_height;
        info!(target: "callback", "Executing balances with dump folder: {} ...", &self.dump_folder.display());
        Ok(())
    }

    /// For each transaction in the block
    ///   1. apply input transactions (remove (TxID == prevTxIDOut and prevOutID == spentOutID))
    ///   2. apply output transactions (add (TxID + curOutID -> HashMapVal))
    ///
    /// For each address, retain:
    ///   * block height as "last modified"
    ///   * output_val
    ///   * address
    fn on_block(&mut self, block: &Block, block_height: u64) -> Result<()> {
        let timestamp = block.header.value.timestamp;
        for tx in &block.txs {
            // process inputs
            for input in &tx.value.inputs {
                let key = input.outpoint.to_bytes();
                if let Some(unspent) = self.unspents.remove(&key) {
                    let stats = self
                        .stats
                        .entry(unspent.address.clone())
                        .or_default();
                    stats.balance = stats.balance.saturating_sub(unspent.value);
                    stats.total_sent += unspent.value;
                    if stats.first_spent_time.is_none() {
                        stats.first_spent_time = Some(timestamp);
                    }
                    stats.last_spent_time = Some(timestamp);

                    if stats.pubkey.is_none() {
                        if let Some(pk) = extract_pubkey_from_script_sig(&input.script_sig) {
                            stats.pubkey = Some(pk);
                        }
                    }
                }
            }

            // process outputs
            for (i, output) in tx.value.outputs.iter().enumerate() {
                if let Some(address) = &output.script.address {
                    let key = TxOutpoint::new(tx.hash, i as u32).to_bytes();
                    let unspent = common::UnspentValue {
                        block_height,
                        value: output.out.value,
                        address: address.clone(),
                    };
                    self.unspents.insert(key, unspent);

                    let stats = self.stats.entry(address.clone()).or_default();
                    stats.balance += output.out.value;
                    stats.total_received += output.out.value;
                    if stats.first_received_time.is_none() {
                        stats.first_received_time = Some(timestamp);
                    }
                    stats.last_received_time = Some(timestamp);

                    if stats.pubkey.is_none() {
                        if let Some(pk) = extract_pubkey_from_script_pubkey(&output.out.script_pubkey, &output.script.pattern) {
                            stats.pubkey = Some(pk);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn on_complete(&mut self, block_height: u64) -> Result<()> {
        self.end_height = block_height;

        self.writer.write_all(
            b"address;balance;pubkey;total sent;total received;first spent time;last spent time;first received time;last received time\n",
        )?;

        for (address, stats) in &self.stats {
            if !self.keep_zero_balances && stats.balance == 0 {
                continue;
            }

            let line = format!(
                "{};{};{};{};{};{};{};{};{}\n",
                address,
                stats.balance,
                stats.pubkey.clone().unwrap_or_default(),
                stats.total_sent,
                stats.total_received,
                stats
                    .first_spent_time
                    .map_or(String::new(), |v| v.to_string()),
                stats
                    .last_spent_time
                    .map_or(String::new(), |v| v.to_string()),
                stats
                    .first_received_time
                    .map_or(String::new(), |v| v.to_string()),
                stats
                    .last_received_time
                    .map_or(String::new(), |v| v.to_string())
            );
            self.writer.write_all(line.as_bytes())?;
        }

        fs::rename(
            self.dump_folder.as_path().join("balances.csv.tmp"),
            self.dump_folder.as_path().join(format!(
                "balances-{}-{}.csv",
                self.start_height, self.end_height
            )),
        )
        .expect("Unable to rename tmp file!");

        info!(
            target: "callback",
            "Done.\nDumped {} addresses.",
            self.stats.len()
        );
        Ok(())
    }
}

fn extract_pubkey_from_script_sig(script: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < script.len() {
        let op = script[i] as usize;
        if op >= 1 && op <= 75 {
            if i + 1 + op > script.len() {
                break;
            }
            let data = &script[i + 1..i + 1 + op];
            if op == 33 || op == 65 {
                return Some(utils::arr_to_hex(data));
            }
            i += 1 + op;
        } else if op == 0x4c {
            if i + 1 >= script.len() {
                break;
            }
            let len = script[i + 1] as usize;
            if i + 2 + len > script.len() {
                break;
            }
            let data = &script[i + 2..i + 2 + len];
            if len == 33 || len == 65 {
                return Some(utils::arr_to_hex(data));
            }
            i += 2 + len;
        } else {
            i += 1;
        }
    }
    None
}

fn extract_pubkey_from_script_pubkey(script: &[u8], pattern: &ScriptPattern) -> Option<String> {
    match pattern {
        ScriptPattern::Pay2PublicKey => {
            if script.len() >= 35 && (script[0] == 33 || script[0] == 65) {
                let len = script[0] as usize;
                if script.len() >= len + 2 {
                    return Some(utils::arr_to_hex(&script[1..1 + len]));
                }
            }
            None
        }
        _ => None,
    }
}
