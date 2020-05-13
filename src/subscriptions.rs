use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::hex::FromHex;

use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDb, DynamoDbClient, ScanInput};

use std::default::Default;
use std::env;
use std::format;

use crate::errors::*;

pub struct SubscriptionsManager {}

impl SubscriptionsManager {

    pub fn get_script_hashes() -> Result<Vec<Sha256dHash>> {
        let client = DynamoDbClient::new(Region::UsWest2);

        let mut script_hashes = vec![];
        let mut last_evaluated_key = None;
        let mut i = 0;

        loop {
            println!("in loop");
            // loop until no more pages (1MB limit)
            let scan_input = ScanInput {
                table_name: format!("{}_AddressInfo", env::var("ENV").unwrap_or(String::from("dev"))),
                projection_expression: Some(String::from("electrumHash")),
                exclusive_start_key: last_evaluated_key.clone(),
                ..Default::default()
            };

            match client.scan(scan_input).sync() {
                Ok(output) => {
                    match output.items {
                        Some(items) => {
                            let mut page_script_hashes = vec![];
                            for item in items {
                                let script_hash_attribute_value = item.get("electrumHash").unwrap();
                                let script_hash_str = script_hash_attribute_value.s.as_ref().unwrap();
                                let script_hash_res = Sha256dHash::from_hex(&script_hash_str);
                                if script_hash_res.is_ok() {
                                    let script_hash = script_hash_res.unwrap();
                                    page_script_hashes.push(script_hash);
                                }
                                i = i + 1;
                            }
                            script_hashes.append(&mut page_script_hashes);
                        },
                        None => {
                            bail!(ErrorKind::DynamoDB("Failed fetching script hashes from DB".to_string()))
                        }
                    };
                    last_evaluated_key = output.last_evaluated_key;
                    if last_evaluated_key.is_none() {
                        break;
                    }
                },
                Err(error) => {
                    bail!(ErrorKind::DynamoDB(error.to_string()))
                }
            }
        }

        Ok(script_hashes)
    }
}