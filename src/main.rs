use anyhow::{Error, Result};
use aptos::common::types::{CliCommand, MovePackageDir};
use aptos::common::utils;
use aptos::move_tool::CompileScript;
use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::rest_client::Client;
use aptos_sdk::transaction_builder::TransactionFactory;
use aptos_sdk::types::LocalAccount;
use aptos_types::account_address::AccountAddress;
use aptos_types::transaction::{
    Script, SignedTransaction, TransactionArgument, TransactionPayload,
};
use ed25519_dalek::{PublicKey, SecretKey};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tiny_keccak::{Hasher, Sha3};

mod script_format;
use script_format::SCRIPT;

const PRIVATE_KEY: &str = "0x10"; // ed25519 privatekey
const APTOS_RPC: &str = "http://127.0.0.1:8080";

const FILE_PATH: &str = "./aptos-script/sources/handle_multi.move";
const SCRIPT_BINARY: &str = "./test.mv";
const GAS_LIMIT: u64 = 100000;

struct AptosClient {
    rest_client: Client,
}

/// An Aptos Account
pub struct Account {
    signing_key: SecretKey,
    sender_key: Ed25519PrivateKey,
}

impl Account {
    /// Load from raw secret key
    pub fn from_secret_key(input: String) -> Result<Self, Error> {
        let input = input.trim_start_matches("0x");
        let h = hex::decode(input)?;
        let signing_key = SecretKey::from_bytes(&h)?;
        let sender_key = Ed25519PrivateKey::try_from(&*signing_key.to_bytes().to_vec())?;
        Ok(Account {
            signing_key,
            sender_key,
        })
    }

    /// Returns the address associated with the given account
    pub fn address(&self) -> String {
        self.auth_key()
    }

    /// Returns the auth_key for the associated account
    pub fn auth_key(&self) -> String {
        let mut sha3 = Sha3::v256();
        sha3.update(PublicKey::from(&self.signing_key).as_bytes());
        sha3.update(&[0u8]);

        let mut output = [0u8; 32];
        sha3.finalize(&mut output);
        hex::encode(output)
    }

    /// Get the account's address
    pub fn to_address(&self) -> Result<AccountAddress, Error> {
        AccountAddress::from_hex_literal(&format!("0x{}", self.address())).map_err(|e| e.into())
    }

    /// Constructs a transaction from a payload and sign it
    pub async fn setup_transaction(
        &self,
        payload: &TransactionPayload,
        rest_client: &Client,
        sequence_number: u64,
        gas_config: u64,
    ) -> Result<SignedTransaction, Error> {
        let transaction_factory = TransactionFactory::new(utils::chain_id(rest_client).await?)
            .with_gas_unit_price(100)
            .with_max_gas_amount(gas_config);

        let sender_key = self.sender_key.clone();
        let sender_account =
            &mut LocalAccount::new(self.to_address()?, sender_key, sequence_number);
        Ok(sender_account
            .sign_with_transaction_builder(transaction_factory.payload(payload.clone())))
    }

    /// Get the current sequence number for this account
    pub async fn get_seq_num(&self, rest_client: &Client) -> Result<u64, Error> {
        utils::get_sequence_number(rest_client, self.to_address()?)
            .await
            .map_err(|e| e.into())
    }
}

impl AptosClient {
    /// Represents an account as well as the private, public key-pair for the Aptos blockchain.
    pub fn new(url: String) -> Result<Self, Error> {
        let url = url.parse::<reqwest::Url>().map(|url| Self {
            rest_client: Client::new(url),
        })?;
        Ok(url)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let aptos_client = AptosClient::new(APTOS_RPC.to_string())?;

    // if path already exist then we don't need to recompile
    if !Path::new(SCRIPT_BINARY).exists() {
        let data = SCRIPT.clone().to_string();
        let new_data = data
            .replace(
                "$address",
                "0x7f07ca4fd4b1bc28a6d18348158ca39af540c9d3c703940a5843c5c4b126ebc4",
            )
            .replace("$module", "SupraSValueFeed")
            .replace("$function", "update_public_key");

        // Recreate the file and dump the processed contents to it
        let mut dst = fs::File::create(&FILE_PATH)?;
        dst.write(new_data.as_bytes())?;

        let move_package = MovePackageDir::new(PathBuf::from("./aptos-script"));
        let compile_script = CompileScript {
            output_file: Some(PathBuf::from(SCRIPT_BINARY)),
            move_options: move_package,
        };
        let latency = Instant::now();
        let _ = compile_script.execute_serialized().await;
        println!("Compile Time: {:?}", latency.elapsed().as_millis());
    }

    // let script_bytes = include_bytes!("../test.mv").to_vec();

    let latency = Instant::now();
    let mut file = fs::File::open(SCRIPT_BINARY)?;
    let mut script_bytes = Vec::<u8>::new();
    file.read_to_end(&mut script_bytes)?;
    println!("Read Time: {:?}", latency.elapsed().as_micros());

    let account = Account::from_secret_key(PRIVATE_KEY.to_string())?;
    let script = Script::new(
        script_bytes,
        vec![],
        vec![TransactionArgument::U8Vector(vec![
            163, 44, 81, 2, 99, 5, 114, 138, 174, 20, 255, 112, 148, 180, 60, 255, 240, 95, 253,
            197, 127, 95, 221, 235, 68, 240, 157, 18, 140, 132, 10, 209, 114, 136, 136, 214, 174,
            160, 31, 237, 194, 102, 99, 80, 151, 72, 64, 10,
        ])],
    );
    let payload = TransactionPayload::Script(script);

    let sequence_number = account.get_seq_num(&aptos_client.rest_client).await?;
    let tx = account
        .setup_transaction(
            &payload,
            &aptos_client.rest_client,
            sequence_number,
            GAS_LIMIT,
        )
        .await?;
    let response = aptos_client
        .rest_client
        .submit_and_wait(&tx)
        .await?
        .into_inner();
    println!("response: {:?}", response.transaction_info()?.hash);

    Ok(())
}
