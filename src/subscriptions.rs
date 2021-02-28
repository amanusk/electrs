use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::hex::FromHex;

use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDb, DynamoDbClient, ScanInput};
use rusoto_sqs::{ReceiveMessageRequest, Sqs, SqsClient, DeleteMessageRequest, GetQueueUrlRequest, GetQueueUrlResult};

use std::default::Default;
use std::env;
use std::format;

use crate::errors::*;
use std::collections::HashMap;
use serde_json::Value;

pub struct SubscriptionsManager {}

impl SubscriptionsManager {

    pub fn get_script_hashes() -> Result<HashMap<Sha256dHash, Value>> {
        let client = DynamoDbClient::new(Region::UsWest2);

        let mut script_hashes = HashMap::new();
        let mut last_evaluated_key = None;
        // we need an alias for "status" because that happens to be a saved word
        let mut expression_attribute_names = HashMap::new();
        expression_attribute_names.insert(String::from("#statusHash"), String::from("status"));

        loop {
            // loop until no more pages (1MB limit)
            let scan_input = ScanInput {
                table_name: format!("{}_AddressInfo", env::var("ENV").unwrap_or(String::from("dev"))),
                projection_expression: Some(String::from("electrumHash, #statusHash")),
                expression_attribute_names: Some(expression_attribute_names.clone()),
                exclusive_start_key: last_evaluated_key.clone(),
                ..Default::default()
            };

            match client.scan(scan_input).sync() {
                Ok(output) => {
                    match output.items {
                        Some(items) => {
                            for item in items {
                                let script_hash_attribute_value = item.get("electrumHash").unwrap();
                                let script_hash_str = script_hash_attribute_value.s.as_ref().unwrap();
                                let script_hash_res = Sha256dHash::from_hex(&script_hash_str);
                                if script_hash_res.is_ok() {
                                    let script_hash = script_hash_res.unwrap();

                                    let status_hash_attribute_value_option = item.get("status");
                                    let status_hash_str_option =
                                        match status_hash_attribute_value_option {
                                            Some(attr_value) => &attr_value.s,
                                            None => &None,
                                        };
                                    let status_hash = match status_hash_str_option {
                                        Some(s) => json!(s),
                                        None => Value::Null,
                                    };

                                    debug!("subscribing script_hash = {:?}, status_hash = {:?}", script_hash, status_hash);
                                    script_hashes.insert(script_hash, status_hash);
                                }
                            }
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

    pub fn subscribe_script_hash_sqs_poller() {
        let sqs = SqsClient::new(Region::UsWest2);

        let mut res = SubscriptionsManager::get_az();
        let az = res.split_off(res.len() - 2).to_uppercase();
        let env = env::var("ENV").unwrap_or(String::from("dev"));

        let queue_name = format!("Electrum_address_subscription_{}_AZ_{}", env, az);

        let get_queue_by_name_request = GetQueueUrlRequest {
            queue_name: queue_name.clone(),
            ..Default::default()
        };

        let response: GetQueueUrlResult = sqs
            .get_queue_url(get_queue_by_name_request)
            .sync()
            .expect("Get queue by URL request failed");

        let queue_url = &response
            .queue_url
            .expect("Queue url should be available from list queues");

        let receive_request = ReceiveMessageRequest {
            queue_url: queue_url.clone(),
            wait_time_seconds: Some(20),
            ..Default::default()
        };

        loop {
            let response = sqs.receive_message(receive_request.clone()).sync();
            for msg in response
                .expect("Expected to have a receive message response")
                .messages
                .expect("message should be available")
                {
                    println!(
                        "Received message '{}' with id {}",
                        msg.body.clone().unwrap(),
                        msg.message_id.clone().unwrap()
                    );
                    println!("Receipt handle is {:?}", msg.receipt_handle);

                    let delete_message_request = DeleteMessageRequest {
                        queue_url: queue_url.clone(),
                        receipt_handle: msg.receipt_handle.clone().unwrap(),
                    };
                    match sqs.delete_message(delete_message_request).sync() {
                        Ok(_) => println!(
                            "Deleted message via receipt handle {:?}",
                            msg.receipt_handle
                        ),
                        Err(e) => panic!("Couldn't delete message: {:?}", e),
                    }
                }
        }
    }

    fn get_az() -> String {
        let res = reqwest::blocking::get("http://instance-data/latest/meta-data/placement/availability-zone");
        if res.is_ok() {
            return res.unwrap().text().unwrap();
        } else {
            return String::from("us-west-2c");
        }
    }
}