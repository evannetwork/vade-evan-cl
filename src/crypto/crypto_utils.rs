/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

use crate::crypto::crypto_datatypes::AssertionProof;
use data_encoding::BASE64URL;
use secp256k1::{recover, Message, RecoveryId, Signature};
use serde::{Deserialize, Serialize};
use serde_json::{value::RawValue, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::{convert::TryInto, error::Error};
use vade_evan_substrate::signing::Signer;

#[cfg(not(target_arch = "wasm32"))]
use chrono::Utc;

#[derive(Serialize, Deserialize, Debug)]
pub struct JwsData<'a> {
    #[serde(borrow)]
    pub doc: &'a RawValue,
}

/// Creates proof for VC document
///
/// # Arguments
/// * `vc` - vc to create proof for
/// * `verification_method` - issuer of VC
/// * `private_key` - private key to create proof as 32B hex string
/// * `signer` - `Signer` to sign with
///
/// # Returns
/// * `AssertionProof` - Proof object containing a JWT and metadata
pub async fn create_assertion_proof(
    document_to_sign: &Value,
    verification_method: &str,
    issuer: &str,
    private_key: &str,
    signer: &Box<dyn Signer>,
) -> Result<AssertionProof, Box<dyn Error>> {
    // create to-be-signed jwt
    let header_str = r#"{"typ":"JWT","alg":"ES256K-R"}"#;
    let padded = BASE64URL.encode(header_str.as_bytes());
    let header_encoded = padded.trim_end_matches('=');
    debug!("header base64 url encoded: {:?}", &header_encoded);

    #[cfg(target_arch = "wasm32")]
    let now: String = js_sys::Date::new_0().to_iso_string().to_string().into();
    #[cfg(not(target_arch = "wasm32"))]
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string();

    // build data object and hash
    let mut data_json: Value = serde_json::from_str("{}")?;
    let doc_clone: Value = document_to_sign.clone();
    data_json["iat"] = Value::from(now.clone());
    data_json["doc"] = doc_clone;
    data_json["iss"] = Value::from(issuer);
    let padded = BASE64URL.encode(format!("{}", &data_json).as_bytes());
    let data_encoded = padded.trim_end_matches('=');
    debug!("data base64 url encoded: {:?}", &data_encoded);

    // create hash of data (including header)
    let header_and_data = format!("{}.{}", header_encoded, data_encoded);
    let mut hasher = Sha256::new();
    hasher.input(&header_and_data);
    let hash = hasher.result();
    debug!("header_and_data hash {:?}", hash);

    // sign this hash
    let hash_arr: [u8; 32] = hash.try_into().map_err(|_| "slice with incorrect length")?;
    let message = format!("0x{}", &hex::encode(hash_arr));
    let (sig_and_rec, _): ([u8; 65], _) = signer.sign_message(&message, &private_key).await?;
    let padded = BASE64URL.encode(&sig_and_rec);
    let sig_base64url = padded.trim_end_matches('=');
    debug!("signature base64 url encoded: {:?}", &sig_base64url);

    // build proof property as serde object
    let jws: String = format!("{}.{}", &header_and_data, sig_base64url);

    let proof = AssertionProof {
        r#type: "EcdsaPublicKeySecp256k1".to_string(),
        created: now,
        proof_purpose: "assertionMethod".to_string(),
        verification_method: verification_method.to_string(),
        jws,
    };

    Ok(proof)
}

/// Checks given Vc document.
/// A Vc document is considered as valid if returning ().
/// Resolver may throw to indicate
/// - that it is not responsible for this Vc
/// - that it considers this Vc as invalid
///
/// Currently the test `vc_id` `"test"` is accepted as valid.
///
/// Not used for the moment but we might need it later.
///
/// # Arguments
///
/// * `vc_id` - vc_id to check document for
/// * `value` - value to check
#[allow(dead_code)]
pub fn check_assertion_proof(
    vc_document: &str,
    signer_address: &str,
) -> Result<(), Box<dyn Error>> {
    let mut vc: Value = serde_json::from_str(vc_document)?;
    if vc["proof"].is_null() {
        debug!("vcs without a proof are considered as valid");
        Ok(())
    } else {
        debug!("checking vc document");

        // separate proof and vc document (vc document will be a Map after this)
        let vc_without_proof = vc
            .as_object_mut()
            .ok_or("could not get vc object as mutable")?;
        let vc_proof = vc_without_proof
            .remove("proof")
            .ok_or("could not remove proof from vc")?;

        // recover address and payload text (pure jwt format)
        let (address, decoded_payload_text) = recover_address_and_data(
            vc_proof["jws"]
                .as_str()
                .ok_or("could not get jws from vc proof")?,
        )?;

        debug!("checking if document given and document from jws are equal");
        let jws: JwsData = serde_json::from_str(&decoded_payload_text)?;
        let doc = jws.doc.get();
        // parse recovered vc document into serde Map
        let parsed_caps1: Value = serde_json::from_str(&doc)?;
        let parsed_caps1_map = parsed_caps1
            .as_object()
            .ok_or("could not get jws doc as object")?;
        // compare documents
        if vc_without_proof != parsed_caps1_map {
            return Err(Box::from(
                "recovered VC document and given VC document do not match",
            ));
        }

        debug!("checking proof of vc document");
        let address = format!("0x{}", address);
        let key_to_use = vc_proof["verificationMethod"]
            .as_str()
            .ok_or("could not get verificationMethod from proof")?;
        debug!("recovered address; {}", &address);
        debug!("key to use for verification; {}", &key_to_use);
        if address != signer_address {
            return Err(Box::from(
                "recovered and signing given address do not match",
            ));
        }

        debug!("vc document is valid");
        Ok(())
    }
}

/// Recovers Ethereum address of signer and data part of a jwt.
///
/// Not used for the moment but we might need it later.
///
/// # Arguments
/// * `jwt` - jwt as str&
///
/// # Returns
/// * `(String, String)` - (Address, Data) tuple
#[allow(dead_code)]
pub fn recover_address_and_data(jwt: &str) -> Result<(String, String), Box<dyn Error>> {
    // jwt text parsing
    let split: Vec<&str> = jwt.split('.').collect();
    let (header, data, signature) = (split[0], split[1], split[2]);
    let header_and_data = format!("{}.{}", header, data);

    // recover data for later checks
    let data_decoded = match BASE64URL.decode(data.as_bytes()) {
        Ok(decoded) => decoded,
        Err(_) => match BASE64URL.decode(format!("{}=", data).as_bytes()) {
            Ok(decoded) => decoded,
            Err(_) => match BASE64URL.decode(format!("{}==", data).as_bytes()) {
                Ok(decoded) => decoded,
                Err(_) => BASE64URL.decode(format!("{}===", data).as_bytes())?,
            },
        },
    };
    let data_string = String::from_utf8(data_decoded)?;

    // decode signature for validation
    let signature_decoded = match BASE64URL.decode(signature.as_bytes()) {
        Ok(decoded) => decoded,
        Err(_) => match BASE64URL.decode(format!("{}=", signature).as_bytes()) {
            Ok(decoded) => decoded,
            Err(_) => BASE64URL.decode(format!("{}==", signature).as_bytes())?,
        },
    };
    debug!("signature_decoded {:?}", &signature_decoded);
    debug!("signature_decoded.len {:?}", signature_decoded.len());

    // create hash of data (including header)
    let mut hasher = Sha256::new();
    hasher.input(&header_and_data);
    let hash = hasher.result();
    debug!("header_and_data hash {:?}", hash);

    // prepare arguments for public key recovery
    let hash_arr: [u8; 32] = hash
        .try_into()
        .map_err(|_| "header_and_data hash invalid")?;
    let ctx_msg = Message::parse(&hash_arr);
    let mut signature_array = [0u8; 64];
    signature_array[..64].clone_from_slice(&signature_decoded[..64]);
    // slice signature and recovery for recovery
    debug!("recovery id; {}", signature_decoded[64]);
    let ctx_sig = Signature::parse(&signature_array);
    let signature_normalized = if signature_decoded[64] < 27 {
        signature_decoded[64]
    } else {
        signature_decoded[64] - 27
    };
    let recovery_id = RecoveryId::parse(signature_normalized)?;

    // recover public key, build ethereum address from it
    let recovered_key = recover(&ctx_msg, &ctx_sig, &recovery_id)?;
    let mut hasher = Keccak256::new();
    hasher.input(&recovered_key.serialize()[1..65]);
    let hash = hasher.result();
    debug!("recovered_key hash {:?}", hash);
    let address = hex::encode(&hash[12..32]);
    debug!("address 0x{}", &address);

    Ok((address, data_string))
}

#[cfg(test)]
mod tests {
    extern crate utilities;

    use super::*;
    use crate::application::datatypes::{CredentialSchema, SchemaProperty};
    use serde::{Deserialize, Serialize};
    use std::{collections::HashMap, env, error::Error};
    use utilities::test_data::{
        accounts::{
            local::{
                SIGNER_1_ADDRESS,
                SIGNER_1_DID,
                SIGNER_1_DID_DOCUMENT_JWS,
                SIGNER_1_PRIVATE_KEY,
            },
            remote::{
                SIGNER_1_PRIVATE_KEY as REMOTE_SIGNER_1_PRIVATE_KEY,
                SIGNER_1_SIGNED_MESSAGE_HASH as REMOTE_SIGNER_1_SIGNED_MESSAGE_HASH,
            },
        },
        environment::DEFAULT_VADE_EVAN_SIGNING_URL,
        vc_zkp::EXAMPLE_CREDENTIAL_SCHEMA,
    };
    use vade_evan_substrate::signing::{LocalSigner, RemoteSigner, Signer};

    #[derive(Serialize, Deserialize)]
    struct JwsDoc {
        id: String,
        r#type: String,
        name: String,
        author: String,
        description: String,
        properties: HashMap<String, SchemaProperty>,
        required: Vec<String>,
    }

    #[test]
    fn can_recover_address_and_data_from_signature() {
        let (address, data) = recover_address_and_data(SIGNER_1_DID_DOCUMENT_JWS).unwrap();
        assert_eq!(format!("0x{}", address), SIGNER_1_ADDRESS);

        // if we find these strings, we can assume the recovery is fine
        println!("data: {}", &data);
        assert_eq!(true, data.contains(&format!(r#""id":"{}""#, &SIGNER_1_DID)));
        assert_eq!(
            true,
            data.contains(&format!(
                r##""publicKey":[{{"id":"{}#key-1""##,
                &SIGNER_1_DID
            ))
        );
        assert_eq!(
            true,
            data.contains(&format!(r#"ethereumAddress":"{}"#, &SIGNER_1_ADDRESS))
        );
    }

    #[tokio::test]
    async fn can_create_assertion_proof() -> Result<(), Box<dyn Error>> {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };

        // First deserialize it into a data type or else serde_json will serialize the document into raw unformatted text
        let schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
        let doc_to_sign = serde_json::to_value(&schema).unwrap();
        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
        let proof = create_assertion_proof(
            &doc_to_sign,
            &format!("{}#key-1", &SIGNER_1_DID),
            SIGNER_1_DID,
            &SIGNER_1_PRIVATE_KEY,
            &signer,
        )
        .await
        .unwrap();

        assert_eq!(proof.proof_purpose, "assertionMethod".to_owned());
        assert_eq!(proof.r#type, "EcdsaPublicKeySecp256k1".to_owned());
        assert_eq!(
            proof.verification_method,
            format!("{}#key-1", &SIGNER_1_DID)
        );

        // Recover document from signature and check if it equals the original
        let (address, data) = recover_address_and_data(&proof.jws).unwrap();
        let jws: JwsData = serde_json::from_str(&data).unwrap();
        let doc: JwsDoc = serde_json::from_str(jws.doc.get()).unwrap();
        let orig: JwsDoc = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
        assert_eq!(
            serde_json::to_string(&doc).unwrap(),
            serde_json::to_string(&orig).unwrap()
        );
        assert_eq!(format!("0x{}", address), SIGNER_1_ADDRESS);

        Ok(())
    }

    #[tokio::test]
    async fn can_sign_messages_remotely() -> Result<(), Box<dyn Error>> {
        let signer: Box<dyn Signer> = Box::new(RemoteSigner::new(
            env::var("VADE_EVAN_SIGNING_URL")
                .unwrap_or_else(|_| DEFAULT_VADE_EVAN_SIGNING_URL.to_string()),
        ));
        let (_signature, message): ([u8; 65], [u8; 32]) = signer
            .sign_message("one two three four", REMOTE_SIGNER_1_PRIVATE_KEY)
            .await?;
        let message_hash = format!("0x{}", hex::encode(message));
        assert_eq!(message_hash, REMOTE_SIGNER_1_SIGNED_MESSAGE_HASH);

        Ok(())
    }

    #[tokio::test]
    async fn can_sign_messages_locally() -> Result<(), Box<dyn Error>> {
        let signer = LocalSigner::new();
        let (_signature, message): ([u8; 65], [u8; 32]) = signer
            .sign_message("one two three four", SIGNER_1_PRIVATE_KEY)
            .await?;
        let message_hash = format!("0x{}", hex::encode(message));
        assert_eq!(
            message_hash,
            "0x216f85bc4d561a7c05231d12139a2d1a050c3baf3d33e057b8c25dcb3d7a8b94"
        );

        Ok(())
    }
}
