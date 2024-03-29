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

use crate::{
    application::{
        datatypes::{
            Credential,
            CredentialDefinition,
            CredentialOffer,
            CredentialRequest,
            CredentialSchema,
            CredentialSchemaReference,
            CredentialSignature,
            CredentialSubject,
            DeltaHistory,
            EncodedCredentialValue,
            RevocationIdInformation,
            RevocationRegistryDefinition,
            RevocationState,
            SchemaProperty,
        },
        prover::Prover,
    },
    crypto::{crypto_issuer::Issuer as CryptoIssuer, crypto_utils::create_assertion_proof},
    utils::utils::{generate_uuid, get_now_as_iso_string},
};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
};
use ursa::cl::{
    new_nonce,
    CredentialPrivateKey,
    RevocationKeyPrivate,
    RevocationRegistry,
    RevocationRegistryDelta,
    RevocationTailsGenerator,
};
use vade_signer::Signer;

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
use wasm_timer::{SystemTime, UNIX_EPOCH};

/// Holds the logic needed to issue and revoke credentials.
pub struct Issuer {}

impl Issuer {
    pub fn new() -> Issuer {
        Issuer {}
    }

    /// Creates a new credential definition for a `CredentialSchema`. The definition needs to be stored
    /// in a publicly available and temper-proof way.
    ///
    /// Safe prime numbers can be given with `p_safe` and `q_safe` to speed up key generation.
    /// Either both or none of them can be provided. Then can be generated with
    /// `ursa::helpers::generate_safe_prime`.
    ///
    /// # Arguments
    /// * `assigned_did` - DID to be used to revoke this credential definition
    /// * `issuer_did` - DID of the issuer
    /// * `schema` - The `CredentialSchema` this definition belongs to
    /// * `issuer_public_key_did` - DID of the public key to check the assertion proof of the definition document
    /// * `issuer_proving_key` - Private key used to create the assertion proof
    /// * `signer` - `Signer` to sign with
    ///
    /// # Returns
    /// * `CredentialDefinition` - The definition object to be saved in a publicly available and temper-proof way
    /// * `CredentialPrivateKey` - The private key used to sign credentials. Needs to be stored privately & securely
    pub async fn create_credential_definition(
        assigned_did: &str,
        issuer_did: &str,
        schema: &CredentialSchema,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        signer: &Box<dyn Signer>,
    ) -> Result<(CredentialDefinition, CredentialPrivateKey), Box<dyn Error>> {
        let created_at = get_now_as_iso_string();
        let (credential_private_key, crypto_credential_def) =
            CryptoIssuer::create_credential_definition(&schema)?;
        let mut definition = CredentialDefinition {
            id: assigned_did.to_owned(),
            r#type: "EvanZKPCredentialDefinition".to_string(),
            issuer: issuer_did.to_owned(),
            schema: schema.id.to_owned(),
            created_at,
            public_key: crypto_credential_def.public_key,
            public_key_correctness_proof: crypto_credential_def.credential_key_correctness_proof,
            proof: None,
        };

        let document_to_sign = serde_json::to_value(&definition)?;

        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            &issuer_did,
            &issuer_proving_key,
            &signer,
        )
        .await?;

        definition.proof = Some(proof);

        Ok((definition, credential_private_key))
    }

    /// Creates a new credential schema specifying properties credentials issued under this schema need to incorporate.
    /// The schema needs to be stored in a publicly available and temper-proof way.
    ///
    /// # Arguments
    /// * `assigned_did` - DID to be used to resolve this credential definition
    /// * `issuer_did` - DID of the issuer
    /// * `schema_name` - Name of the schema
    /// * `description` - Description for the schema. Can be left blank
    /// * `properties` - The properties of the schema as Key-Object pairs#
    /// * `required_properties` - The keys of properties that need to be provided when issuing a credential under this schema.
    /// * `allow_additional_properties` - Specifies whether a credential under this schema is considered valid if it specifies more properties than the schema specifies.
    /// * `issuer_public_key_did` - DID of the public key to check the assertion proof of the definition document
    /// * `issuer_proving_key` - Private key used to create the assertion proof
    /// * `signer` - `Signer` to sign with
    ///
    /// # Returns
    /// * `CredentialSchema` - The schema object to be saved in a publicly available and temper-proof way
    pub async fn create_credential_schema(
        assigned_did: &str,
        issuer_did: &str,
        schema_name: &str,
        description: &str,
        properties: HashMap<String, SchemaProperty>,
        required_properties: Vec<String>,
        allow_additional_properties: bool,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        signer: &Box<dyn Signer>,
    ) -> Result<CredentialSchema, Box<dyn Error>> {
        let created_at = get_now_as_iso_string();

        let mut schema = CredentialSchema {
            id: assigned_did.to_owned(),
            r#type: "EvanVCSchema".to_string(), //TODO: Make enum
            name: schema_name.to_owned(),
            author: issuer_did.to_owned(),
            created_at,
            description: description.to_owned(),
            properties,
            required: required_properties,
            additional_properties: allow_additional_properties,
            proof: None,
        };

        let document_to_sign = serde_json::to_value(&schema)?;

        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            &issuer_did,
            &issuer_proving_key,
            &signer,
        )
        .await?;

        schema.proof = Some(proof);

        Ok(schema)
    }

    /// Creates a new revocation registry definition. This definition is used to prove the non-revocation state of a credential.
    /// It needs to be publicly published and updated after every revocation. The definition is signed by the issuer.
    ///
    /// # Arguments
    /// * `assigned_did` - DID that will point to the registry definition
    /// * `credential_definition` - Credential definition this revocation registry definition will be associated with
    /// * `issuer_public_key_did` - DID of the public key that will be associated with the created signature
    /// * `issuer_proving_key` - Private key of the issuer used for signing the definition
    /// * `signer` - `Signer` to sign with
    /// * `maximum_credential_count` - Capacity of the revocation registry in terms of issuable credentials
    ///
    /// # Returns
    /// A 3-tuple consisting
    /// * `RevocationRegistryDefinition` - the definition
    /// * `RevocationKeyPrivate` - the according revocation private key, and an revocation
    /// * `RevocationIdInformation` - object used for keeping track of issued revocation IDs
    pub async fn create_revocation_registry_definition(
        assigned_did: &str,
        credential_definition: &CredentialDefinition,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        signer: &Box<dyn Signer>,
        maximum_credential_count: u32,
    ) -> Result<
        (
            RevocationRegistryDefinition,
            RevocationKeyPrivate,
            RevocationIdInformation,
        ),
        Box<dyn Error>,
    > {
        let (crypto_rev_def, rev_key_private) = CryptoIssuer::create_revocation_registry(
            &credential_definition.public_key,
            maximum_credential_count,
        )?;

        let updated_at = get_now_as_iso_string();

        let delta_history = DeltaHistory {
            created: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "Error generating unix timestamp for delta history")?
                .as_secs(),
            delta: crypto_rev_def.registry_delta.clone(),
        };

        let mut rev_reg_def = RevocationRegistryDefinition {
            id: assigned_did.to_string(),
            credential_definition: credential_definition.id.to_string(),
            registry: crypto_rev_def.registry,
            registry_delta: crypto_rev_def.registry_delta,
            delta_history: vec![delta_history],
            maximum_credential_count,
            revocation_public_key: crypto_rev_def.revocation_public_key,
            tails: crypto_rev_def.tails,
            updated_at,
            proof: None,
        };

        let revoc_info = RevocationIdInformation {
            definition_id: assigned_did.to_string(),
            next_unused_id: 1, // needs to start at 1
            used_ids: HashSet::new(),
        };

        let document_to_sign = serde_json::to_value(&rev_reg_def)?;
        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            &credential_definition.issuer,
            &issuer_proving_key,
            &signer,
        )
        .await?;

        rev_reg_def.proof = Some(proof);

        Ok((rev_reg_def, rev_key_private, revoc_info))
    }

    /// Issue a new credential, based on a credential request received by the credential subject
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer
    /// * `subject_did` - DID of the subject
    /// * `credential_request` - Credential request object sent by the subject
    /// * `credential_definition` - Credential definition to use for issuance as specified by the credential request
    /// * `credential_private_key` - Issuer's private key associated with the credential definition
    /// * `credential_schema` - Credential schema to be used as specified by the credential request
    /// * `revocation_registry_definition` - Revocation registry definition to be used for issuance
    /// * `revocation_private_key` - Private key associated to the revocation registry definition
    /// * `revocation_info` - Revocation info containing ID counter. Hold by credential definition owner
    /// * `issuance_date` - issuance date for credential, defaults to now, must be a date in the future if provided
    ///
    /// # Returns
    /// Tuple containing
    /// * `Credential` - Issued credential
    /// * `RevocationIdInformation` - Updated `revocation_info` object that needs to be persisted
    pub fn issue_credential(
        issuer_did: &str,
        subject_did: &str,
        credential_request: CredentialRequest,
        credential_definition: CredentialDefinition,
        credential_private_key: CredentialPrivateKey,
        credential_schema: CredentialSchema,
        revocation_registry_definition: &mut RevocationRegistryDefinition,
        revocation_private_key: RevocationKeyPrivate,
        revocation_info: &RevocationIdInformation,
        issuance_date: Option<String>,
    ) -> Result<(Credential, RevocationState, RevocationIdInformation), Box<dyn Error>> {
        let mut data: HashMap<String, EncodedCredentialValue> = HashMap::new();
        //
        // Optional value handling
        //
        let mut processed_credential_request: CredentialRequest =
            serde_json::from_str(&serde_json::to_string(&credential_request)?)?;
        let mut null_values: HashMap<String, String> = HashMap::new();
        for field in &credential_schema.properties {
            if credential_request.credential_values.get(field.0).is_none() {
                for required in &credential_schema.required {
                    if required.eq(field.0) {
                        // No value provided for required schema property
                        let error = format!("Missing required schema property; {}", field.0);
                        return Err(Box::from(error));
                    }
                }
                null_values.insert(field.0.clone(), "null".to_owned()); // omitted property is optional, encode it with 'null'
            } else {
                // Add value to credentialSubject part of VC
                let val = credential_request
                    .credential_values
                    .get(field.0)
                    .ok_or("could not get credential subject from request")?
                    .clone();
                data.insert(field.0.to_owned(), val);
            }
        }

        processed_credential_request
            .credential_values
            .extend(Prover::encode_values(null_values)?);

        let credential_subject = CredentialSubject {
            id: subject_did.to_owned(),
            data,
        };

        let schema_reference = CredentialSchemaReference {
            id: credential_schema.id,
            r#type: "EvanZKPSchema".to_string(),
        };

        // Get next unused revocation ID for credential, mark as used & increment counter
        if revocation_info.next_unused_id == revocation_registry_definition.maximum_credential_count
        {
        }
        let rev_idx = revocation_info.next_unused_id;
        let mut used_ids: HashSet<u32> = revocation_info.used_ids.clone();
        if !used_ids.insert(rev_idx) {
            return Err(Box::from("Could not use next revocation ID as it has already been used - Counter information seems to be corrupted"));
        }

        let new_rev_info = RevocationIdInformation {
            definition_id: revocation_registry_definition.id.clone(),
            next_unused_id: rev_idx + 1,
            used_ids,
        };

        let (signature, signature_correctness_proof, issuance_nonce, witness) =
            CryptoIssuer::sign_credential_with_revocation(
                &processed_credential_request,
                &credential_private_key,
                &credential_definition.public_key,
                revocation_registry_definition,
                rev_idx,
                &revocation_private_key,
            )?;

        let credential_id = generate_uuid();

        let delta: RevocationRegistryDelta = serde_json::from_str(&serde_json::to_string(
            &revocation_registry_definition.registry,
        )?)?;

        let revocation_state = RevocationState {
            credential_id: credential_id.clone(),
            revocation_id: rev_idx,
            delta,
            updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "Error generating unix timestamp for delta history")?
                .as_secs(),
            witness,
        };

        let cred_signature = CredentialSignature {
            r#type: "CLSignature2019".to_string(),
            credential_definition: credential_definition.id,
            issuance_nonce,
            signature,
            signature_correctness_proof,
            revocation_id: rev_idx,
            revocation_registry_definition: revocation_registry_definition.id.clone(),
        };

        let credential = Credential {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            id: credential_id,
            r#type: vec!["VerifiableCredential".to_string()],
            issuer: issuer_did.to_owned(),
            issuance_date: issuance_date.unwrap_or_else(get_now_as_iso_string),
            credential_subject,
            credential_schema: schema_reference,
            proof: cred_signature,
        };
        Ok((credential, revocation_state, new_rev_info))
    }

    /// Creates a new credential offer, as a response to a `CredentialProposal` sent by a prover.
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer
    /// * `subject_did` - DID of the subject
    /// * `schema_did` - DID of the `CredentialSchema` to be offered
    /// * `credential_definition_did` - DID of the `CredentialDefinition` to be offered
    ///
    /// # Returns
    /// * `CredentialOffer` - The message to be sent to the prover.
    pub fn offer_credential(
        issuer_did: &str,
        subject_did: &str,
        schema_did: &str,
        credential_definition_did: &str,
    ) -> Result<CredentialOffer, Box<dyn Error>> {
        let nonce = new_nonce().map_err(|e| format!("could not get nonce; {}", &e))?;

        Ok(CredentialOffer {
            issuer: issuer_did.to_owned(),
            subject: subject_did.to_owned(),
            r#type: "EvanZKPCredentialOffering".to_string(),
            schema: schema_did.to_owned(),
            credential_definition: credential_definition_did.to_owned(),
            nonce,
        })
    }

    /// Revokes a credential.
    ///
    /// # Arguments
    /// * `issuer` - DID of the issuer
    /// * `revocation_registry_definition` - Revocation registry definition the credential belongs to
    /// * `revocation_id` - Revocation ID of the credential
    /// * `issuer_public_key_did` - DID of the public key that will be associated with the created signature
    /// * `issuer_proving_key` - Private key of the issuer used for signing the definition
    /// * `signer` - `Signer` to sign with
    ///
    /// # Returns
    /// * `RevocationRegistryDefinition` - The updated revocation registry definition that needs to be stored in the original revocation registry definition's place.
    pub async fn revoke_credential(
        issuer: &str,
        revocation_registry_definition: &RevocationRegistryDefinition,
        revocation_id: u32,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        signer: &Box<dyn Signer>,
    ) -> Result<RevocationRegistryDefinition, Box<dyn Error>> {
        let updated_at = get_now_as_iso_string();

        let delta = CryptoIssuer::revoke_credential(revocation_registry_definition, revocation_id)?;

        let mut full_delta: RevocationRegistryDelta =
            revocation_registry_definition.registry_delta.clone();
        full_delta
            .merge(&delta)
            .map_err(|e| format!("could not create revocation registry delta; {}", &e))?;

        let unix_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Error generating unix timestamp for delta history")?
            .as_secs();
        let delta_history = DeltaHistory {
            created: unix_timestamp,
            delta: delta.clone(),
        };

        let mut history_vec = revocation_registry_definition.delta_history.clone();
        history_vec.push(delta_history);

        let tails: RevocationTailsGenerator = revocation_registry_definition.tails.clone();
        let mut rev_reg_def = RevocationRegistryDefinition {
            id: revocation_registry_definition.id.to_owned(),
            credential_definition: revocation_registry_definition
                .credential_definition
                .to_owned(),
            registry: RevocationRegistry::from(full_delta.clone()),
            registry_delta: full_delta,
            delta_history: history_vec,
            maximum_credential_count: revocation_registry_definition.maximum_credential_count,
            revocation_public_key: revocation_registry_definition.revocation_public_key.clone(),
            tails,
            updated_at,
            proof: None,
        };

        let document_to_sign = serde_json::to_value(&rev_reg_def)?;
        let proof = create_assertion_proof(
            &document_to_sign,
            issuer_public_key_did,
            issuer,
            issuer_proving_key,
            &signer,
        )
        .await?;

        rev_reg_def.proof = Some(proof);

        Ok(rev_reg_def)
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate log;
    extern crate utilities;

    use super::*;
    use crate::{
        application::datatypes::{CredentialSchema, SchemaProperty},
        crypto::crypto_utils::check_assertion_proof,
    };
    use std::{collections::HashMap, error::Error};
    use utilities::test_data::{
        accounts::local::{ISSUER_ADDRESS, ISSUER_DID, ISSUER_PRIVATE_KEY},
        did::{EXAMPLE_DID_1, EXAMPLE_DID_DOCUMENT_1},
        vc_zkp::EXAMPLE_CREDENTIAL_SCHEMA,
    };
    use vade_signer::{LocalSigner, Signer};

    #[tokio::test]
    async fn can_create_schema() -> Result<(), Box<dyn Error>> {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };

        let did_document = serde_json::to_value(&EXAMPLE_DID_DOCUMENT_1)?;
        let mut required_properties: Vec<String> = Vec::new();
        let mut test_properties: HashMap<String, SchemaProperty> = HashMap::new();
        test_properties.insert(
            "test_property_string".to_owned(),
            SchemaProperty {
                r#type: "string".to_owned(),
                format: None,
                items: None,
            },
        );
        required_properties.push("test_property_string".to_owned());

        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
        let schema: CredentialSchema = Issuer::create_credential_schema(
            EXAMPLE_DID_1,
            ISSUER_DID,
            "test_schema",
            "Test description",
            test_properties,
            required_properties,
            false,
            &did_document["publicKey"][0]["id"].to_string(),
            &ISSUER_PRIVATE_KEY,
            &signer,
        )
        .await?;

        assert_eq!(&schema.author, &ISSUER_DID);
        assert_eq!(schema.additional_properties, false);
        let result_property: &SchemaProperty =
            &schema.properties.get("test_property_string").unwrap();
        let expected: SchemaProperty = SchemaProperty {
            r#type: "string".to_owned(),
            format: None,
            items: None,
        };
        assert_eq!(
            serde_json::to_string(&result_property).unwrap(),
            serde_json::to_string(&expected).unwrap(),
        );

        let serialized = serde_json::to_string(&schema).unwrap();
        assert!(match check_assertion_proof(&serialized, ISSUER_ADDRESS) {
            Ok(()) => true,
            Err(e) => panic!("assertion check failed with: {}", e),
        });

        Ok(())
    }

    #[tokio::test]
    async fn can_create_credential_definition() -> Result<(), Box<dyn Error>> {
        let schema: CredentialSchema = serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
        let (definition, _) = Issuer::create_credential_definition(
            &EXAMPLE_DID_1,
            &ISSUER_DID,
            &schema,
            "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1",
            &ISSUER_PRIVATE_KEY,
            &signer,
        )
        .await?;

        assert_eq!(
            serde_json::to_string(&definition.issuer).unwrap(),
            serde_json::to_string(&ISSUER_DID).unwrap(),
        );

        assert_eq!(
            serde_json::to_string(&definition.schema).unwrap(),
            serde_json::to_string(&schema.id).unwrap()
        );

        assert_eq!(&definition.id, EXAMPLE_DID_1);

        let serialized = serde_json::to_string(&definition).unwrap();
        assert!(match check_assertion_proof(&serialized, ISSUER_ADDRESS) {
            Ok(()) => true,
            Err(e) => panic!("assertion check failed with: {}", e),
        });

        Ok(())
    }
}
