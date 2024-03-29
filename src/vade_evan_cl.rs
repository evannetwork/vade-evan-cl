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

use crate::application::{
    datatypes::{
        Credential,
        CredentialDefinition,
        CredentialOffer,
        CredentialPrivateKey,
        CredentialProposal,
        CredentialRequest,
        CredentialSchema,
        CredentialSecretsBlindingFactors,
        MasterSecret,
        ProofPresentation,
        ProofRequest,
        ProofVerification,
        RevocationIdInformation,
        RevocationKeyPrivate,
        RevocationRegistryDefinition,
        RevocationState,
        SchemaProperty,
        SubProofRequest,
    },
    issuer::Issuer,
    prover::Prover,
    verifier::Verifier,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error};
use ursa::cl::{constants::LARGE_PRIME, helpers::generate_safe_prime, Witness};
use vade::{Vade, VadePlugin, VadePluginResultValue};
use vade_signer::Signer;

const EVAN_METHOD: &str = "did:evan";
const EVAN_METHOD_ZKP: &str = "did:evan:zkp";
const PROOF_METHOD_CL: &str = "cl";

macro_rules! parse {
    ($data:expr, $type_name:expr) => {{
        serde_json::from_str($data)
            .map_err(|e| format!("{} when parsing {} {}", &e, $type_name, $data))?
    }};
}

macro_rules! get_document {
    ($vade:expr, $did:expr, $type_name:expr) => {{
        debug!("fetching {} with did; {}", $type_name, $did);
        let resolve_result = $vade.did_resolve($did).await?;
        let result_str = resolve_result[0]
            .as_ref()
            .ok_or_else(|| format!("could not get {} did document", $type_name))?;
        parse!(&result_str, &$type_name)
    }};
}

macro_rules! ignore_unrelated {
    ($method:expr, $options:expr) => {{
        if $method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let type_options: TypeOptions = parse!($options, "options");
        match type_options.r#type.as_deref() {
            Some(PROOF_METHOD_CL) => (),
            _ => return Ok(VadePluginResultValue::Ignored),
        };
    }};
}

/// Message passed to vade containing the desired credential type.
/// Does not perform action if type does not indicate credential type CL.
/// This can be done by passing "cl" as the value for "type".
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeOptions {
    pub r#type: Option<String>,
}

/// Contains information necessary to make on-chain transactions (e.g. updating a DID Document).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationOptions {
    /// Reference to the private key, will be forwarded to external signer if available
    pub private_key: String,
    /// DID of the identity
    pub identity: String,
}

/// API payload needed to create a credential definition needed for issuing credentials
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialDefinitionPayload {
    /// DID of the definition issuer/owner
    pub issuer_did: String,
    /// DID of the schema to issue the definition for
    pub schema_did: String,
    /// DID of the issuer's public key
    pub issuer_public_key_did: String,
    /// Key to sign the credential definition
    pub issuer_proving_key: String,
}

/// API payload needed to create a credential schema needed for issuing credentials
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialSchemaPayload {
    /// DID of the schema issuer/owner
    pub issuer: String,
    /// Name given to the schema
    pub schema_name: String,
    /// A text describing the schema's purpose
    pub description: String,
    /// The properties the schema holds
    pub properties: HashMap<String, SchemaProperty>,
    /// Names of required properties
    pub required_properties: Vec<String>,
    /// Tells a verifier whether properties not found in the schema are to be deemed valid
    pub allow_additional_properties: bool,
    /// DID of the issuer's public key to validate the schema's assertion proof
    pub issuer_public_key_did: String,
    /// Secret key to sign the schema with
    pub issuer_proving_key: String,
}

/// API payload to create a revocation registry definition needed to revoke issued credentials
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRevocationRegistryDefinitionPayload {
    /// DID of the credential definition this revocation registry is linked to
    pub credential_definition: String,
    /// DID of the issuer's public key to validate the registry's assertion proof
    pub issuer_public_key_did: String,
    /// Secret key to sign the registry with
    pub issuer_proving_key: String,
    /// Maximum numbers of credentials to be tracked by this registry
    pub maximum_credential_count: u32,
}

/// Information about a created revocation registry definition
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRevocationRegistryDefinitionResult {
    /// Key needed to revoke credentials
    pub private_key: RevocationKeyPrivate,
    /// Keeps track of used credential IDs and which ID to use next
    pub revocation_info: RevocationIdInformation,
    /// Revocation data, needs to be persisted in a public space
    pub revocation_registry_definition: RevocationRegistryDefinition,
}

/// API payload needed to issue a new credential
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialPayload {
    /// DID of the credential issuer
    pub issuer: String,
    /// Date of issuance
    pub issuance_date: Option<String>,
    /// DID of the credential subject
    pub subject: String,
    /// Credential request sent by the subject
    pub credential_request: CredentialRequest,
    /// DID of the associated revocation definition
    pub credential_revocation_definition: String,
    /// Key to create the credential signature
    pub credential_private_key: CredentialPrivateKey,
    /// Key to make this credential revokable
    pub revocation_private_key: RevocationKeyPrivate,
    /// Tracker of current and next revocation IDs to use
    pub revocation_information: RevocationIdInformation,
}

/// API payload needed to finish a blinded credential signature by a holder/subject
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishCredentialPayload {
    /// The issued credential
    pub credential: Credential,
    /// The associated credential request
    pub credential_request: CredentialRequest,
    /// DID of the revocation registry definition
    pub credential_revocation_definition: String,
    /// Blinding factors created during credential request creation
    pub blinding_factors: CredentialSecretsBlindingFactors,
    /// Master secret to incorporate into the signature
    pub master_secret: MasterSecret,
    /// Current revocation state of the credential
    pub revocation_state: RevocationState,
}

/// Result of a call to issue_credential
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialResult {
    /// The issued credential
    pub credential: Credential,
    /// Tracker of current and next revocation IDs to use
    pub revocation_info: RevocationIdInformation,
    /// Current revocation state of the credential
    pub revocation_state: RevocationState,
}

/// API payload for creating a credential offer as an issuer
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfferCredentialPayload {
    /// DID of the issuer
    pub issuer: String,
    /// DID of the subject
    pub subject: String,
    /// DID of the schema of the credential to be issued
    pub schema: String,
    /// DID of the credential definition of the credential to be issued
    pub credential_definition: String,
}

/// API payload for creating proofs
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentProofPayload {
    /// Proof request sent by a verifier
    pub proof_request: ProofRequest,
    /// Map of credentials referenced by their schema DIDs for all of the requested credentials
    pub credentials: HashMap<String, Credential>,
    /// All of the updated witnesses referenced by their associated credential's schema DID
    pub witnesses: HashMap<String, Witness>,
    /// The holder's master secret
    pub master_secret: MasterSecret,
}

/// API payload for creating a credential proposal
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialProposalPayload {
    /// DID of the issuer
    pub issuer: String,
    /// DID of the subject
    pub subject: String,
    /// DID of the schema
    pub schema: String,
}

/// API payload for creating a credential request
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCredentialPayload {
    /// Credential offering received by an issuer
    pub credential_offering: CredentialOffer,
    /// DID of the schema
    pub credential_schema: String,
    /// The holder's master secret
    pub master_secret: MasterSecret,
    /// Key-value pairs to be signed in the credential
    pub credential_values: HashMap<String, String>,
}

/// API payload for creationg proof requests as a verifier
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestProofPayload {
    /// DID of the verifier
    pub verifier_did: String,
    /// DID of the prover
    pub prover_did: String,
    /// List of subproof requests, each requiring the proof of one credential signature
    pub sub_proof_requests: Vec<SubProofRequest>,
}

/// API payload to revoke a credential
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCredentialPayload {
    /// DID of the issuer
    pub issuer: String,
    /// DID of the associated revocation registry definition
    pub revocation_registry_definition: String,
    /// ID of the credential to be revoked
    pub credential_revocation_id: u32,
    /// DID of the issuer's public key to validate the registry's assertion proof
    pub issuer_public_key_did: String,
    /// Secret key to sign the registry with
    pub issuer_proving_key: String,
}

/// API payload to validate a received proof
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateProofPayload {
    /// Proof received by a holder/prover
    pub presented_proof: ProofPresentation,
    /// Proof request that was sent to the holder/prover
    pub proof_request: ProofRequest,
}

pub struct VadeEvanCl {
    signer: Box<dyn Signer>,
    vade: Vade,
}

impl VadeEvanCl {
    /// Creates new instance of `VadeEvanCl`.
    pub fn new(vade: Vade, signer: Box<dyn Signer>) -> VadeEvanCl {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        VadeEvanCl { signer, vade }
    }
}

impl VadeEvanCl {
    /// Generate new safe prime number with `ursa`'s configured default size.
    /// Can be used to generate values for:
    ///
    /// - payload.p_safe
    /// - payload.q_safe
    ///
    /// for [`vc_zkp_create_credential_definition`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.VadeEvanCl.html#method.vc_zkp_create_credential_definition).
    pub fn generate_safe_prime() -> Result<String, Box<dyn Error>> {
        let bn = generate_safe_prime(LARGE_PRIME)
            .map_err(|err| format!("could not generate safe prime number; {}", &err))?;
        serde_json::to_string(&bn)
            .map_err(|err| Box::from(format!("could not serialize big number; {}", &err)))
    }

    async fn generate_did(
        &mut self,
        private_key: &str,
        identity: &str,
    ) -> Result<String, Box<dyn Error>> {
        let options = format!(
            r###"{{
            "privateKey": "{}",
            "identity": "{}",
            "type": "substrate"
        }}"###,
            private_key, identity
        );
        let result = self
            .vade
            .did_create(EVAN_METHOD_ZKP, &options, &"".to_string())
            .await?;
        if result.is_empty() {
            return Err(Box::from(
                "Could not generate DID as no listeners were registered for this method",
            ));
        }

        let generated_did = result[0]
            .as_ref()
            .ok_or("could not generate DID")?
            .trim_matches('"')
            .to_string();

        Ok(generated_did)
    }

    async fn set_did_document(
        &mut self,
        did: &str,
        payload: &str,
        private_key: &str,
        identity: &str,
    ) -> Result<Option<String>, Box<dyn Error>> {
        let options = format!(
            r###"{{
            "privateKey": "{}",
            "identity": "{}",
            "operation": "setDidDocument",
            "type": "substrate"
        }}"###,
            &private_key, &identity
        );
        let result = self.vade.did_update(&did, &options, &payload).await?;

        if result.is_empty() {
            return Err(Box::from(
                "Could not set did document as no listeners were registered for this method",
            ));
        }

        Ok(Some("".to_string()))
    }
}

#[async_trait(?Send)]
impl VadePlugin for VadeEvanCl {
    /// Runs a custom function, currently supports
    ///
    /// - `create_master_secret` to create new master secrets
    /// - `generate_safe_prime` to generate safe prime numbers for [`vc_zkp_create_credential_definition`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.VadeEvanCl.html#method.vc_zkp_create_credential_definition)
    ///
    /// # Arguments
    ///
    /// * `method` - method to call a function for (e.g. "did:example")
    /// * `function` - currently supports `generate_safe_prime` and `create_master_secret`
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `_payload` - currently not used, so can be left empty
    async fn run_custom_function(
        &mut self,
        method: &str,
        function: &str,
        options: &str,
        _payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        match function {
            "create_master_secret" => Ok(VadePluginResultValue::Success(Some(
                serde_json::to_string(&Prover::create_master_secret()?)?,
            ))),
            "generate_safe_prime" => Ok(VadePluginResultValue::Success(Some(
                VadeEvanCl::generate_safe_prime()?,
            ))),
            _ => Ok(VadePluginResultValue::Ignored),
        }
    }

    /// Creates a new credential definition and stores the public part on-chain. The private part (key) needs
    /// to be stored in a safe way and must not be shared. A credential definition holds cryptographic material
    /// needed to verify proofs. Every definition is bound to one credential schema.
    ///
    /// To improve performance, safe prime numbers that are used to derive keys from **can** be
    /// pre-generated with custom function `generate_safe_prime` which can be called with
    /// [`run_custom_function`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.VadeEvanCl.html#method.run_custom_function).
    /// For these numbers two calls have to be made to create two distinct numbers. They can then
    /// be provided as [`payload.p_safe`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.CreateCredentialDefinitionPayload.html#structfield.p_safe)
    /// and [`payload.q_safe`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.CreateCredentialDefinitionPayload.html#structfield.q_safe).
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential definition for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`CreateCredentialDefinitionPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.CreateCredentialDefinitionPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The created definition as a JSON object
    async fn vc_zkp_create_credential_definition(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: CreateCredentialDefinitionPayload = parse!(&payload, "payload");
        let schema: CredentialSchema = get_document!(&mut self.vade, &payload.schema_did, "schema");

        let generated_did = self
            .generate_did(&options.private_key, &options.identity)
            .await?;

        let (definition, pk) = Issuer::create_credential_definition(
            &generated_did,
            &payload.issuer_did,
            &schema,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized = serde_json::to_string(&(&definition, &pk))?;
        let serialized_definition = serde_json::to_string(&definition)?;
        self.set_did_document(
            &generated_did,
            &serialized_definition,
            &options.private_key,
            &options.identity,
        )
        .await?;

        Ok(VadePluginResultValue::Success(Some(serialized)))
    }

    /// Creates a new zero-knowledge proof credential schema.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential schema for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`CreateCredentialSchemaPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.CreateCredentialSchemaPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The created schema as a JSON object
    async fn vc_zkp_create_credential_schema(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: CreateCredentialSchemaPayload = parse!(&payload, "payload");

        let generated_did = self
            .generate_did(&options.private_key, &options.identity)
            .await?;

        let schema = Issuer::create_credential_schema(
            &generated_did,
            &payload.issuer,
            &payload.schema_name,
            &payload.description,
            payload.properties,
            payload.required_properties,
            payload.allow_additional_properties,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized = serde_json::to_string(&schema)?;
        self.set_did_document(
            &generated_did,
            &serialized,
            &options.private_key,
            &options.identity,
        )
        .await?;

        Ok(VadePluginResultValue::Success(Some(serialized)))
    }

    /// Creates a new revocation registry definition and stores it on-chain. The definition consists of a public
    /// and a private part. The public part holds the cryptographic material needed to create non-revocation proofs.
    /// The private part needs to reside with the registry owner and is used to revoke credentials.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a revocation registry definition for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`CreateRevocationRegistryDefinitionPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.CreateRevocationRegistryDefinitionPayload.html)
    ///
    /// # Returns
    /// * created revocation registry definition as a JSON object as serialized [`CreateRevocationRegistryDefinitionResult`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.CreateRevocationRegistryDefinitionResult.html)
    async fn vc_zkp_create_revocation_registry_definition(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: CreateRevocationRegistryDefinitionPayload = parse!(&payload, "payload");
        let definition: CredentialDefinition = get_document!(
            &mut self.vade,
            &payload.credential_definition,
            "credential definition"
        );

        let generated_did = self
            .generate_did(&options.private_key, &options.identity)
            .await?;

        let (definition, private_key, revocation_info) =
            Issuer::create_revocation_registry_definition(
                &generated_did,
                &definition,
                &payload.issuer_public_key_did,
                &payload.issuer_proving_key,
                &self.signer,
                payload.maximum_credential_count,
            )
            .await?;

        let serialized_def = serde_json::to_string(&definition)?;

        self.set_did_document(
            &generated_did,
            &serialized_def,
            &options.private_key,
            &options.identity,
        )
        .await?;

        let serialized_result = serde_json::to_string(&CreateRevocationRegistryDefinitionResult {
            private_key,
            revocation_info,
            revocation_registry_definition: definition,
        })?;

        Ok(VadePluginResultValue::Success(Some(serialized_result)))
    }

    /// Issues a new credential. This requires an issued schema, credential definition, an active revocation
    /// registry and a credential request message.
    ///
    /// # Arguments
    ///
    /// * `method` - method to issue a credential for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`IssueCredentialPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.IssueCredentialPayload.html)
    ///
    /// # Returns
    /// * serialized [`IssueCredentialResult`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.IssueCredentialResult.html) consisting of the credential, this credential's initial revocation state and
    /// the updated revocation info, only interesting for the issuer (needs to be stored privately)
    async fn vc_zkp_issue_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: IssueCredentialPayload = parse!(&payload, "payload");
        let definition: CredentialDefinition = get_document!(
            &mut self.vade,
            &payload.credential_request.credential_definition,
            "credential definition"
        );
        let schema: CredentialSchema = get_document!(&mut self.vade, &definition.schema, "schema");
        let mut revocation_definition: RevocationRegistryDefinition = get_document!(
            &mut self.vade,
            &payload.credential_revocation_definition,
            "revocation definition"
        );

        let (credential, revocation_state, revocation_info) = Issuer::issue_credential(
            &payload.issuer,
            &payload.subject,
            payload.credential_request,
            definition,
            payload.credential_private_key,
            schema,
            &mut revocation_definition,
            payload.revocation_private_key,
            &payload.revocation_information,
            payload.issuance_date,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &IssueCredentialResult {
                credential,
                revocation_state,
                revocation_info,
            },
        )?)))
    }

    /// Finishes a credential, e.g. by incorporating the prover's master secret into the credential signature after issuance.
    ///
    /// # Arguments
    ///
    /// * `method` - method to update a finish credential for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Returns
    /// * serialized [`Credential`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/application/datatypes/struct.Credential.html) consisting of the credential, this credential's initial revocation state and
    /// the updated revocation info, only interesting for the issuer (needs to be stored privately)
    async fn vc_zkp_finish_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        ignore_unrelated!(method, options);

        // let options: AuthenticationOptions = parse!(&options, "options");
        let payload: FinishCredentialPayload = parse!(&payload, "payload");
        let FinishCredentialPayload {
            mut credential,
            credential_request,
            credential_revocation_definition,
            blinding_factors,
            master_secret,
            revocation_state,
        } = payload;

        let definition: CredentialDefinition = get_document!(
            &mut self.vade,
            &credential_request.credential_definition,
            "credential definition"
        );
        let schema: CredentialSchema = get_document!(&mut self.vade, &definition.schema, "schema");
        let revocation_definition: RevocationRegistryDefinition = get_document!(
            &mut self.vade,
            &credential_revocation_definition,
            "revocation definition"
        );

        Prover::post_process_credential_signature(
            &mut credential,
            &schema,
            &credential_request,
            &definition,
            blinding_factors,
            &master_secret,
            &revocation_definition,
            &revocation_state.witness,
        )?;
        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &credential,
        )?)))
    }

    /// Creates a `CredentialOffer` message. A `CredentialOffer` is sent by an issuer and is the response
    /// to a `CredentialProposal`. The `CredentialOffer` specifies which schema and definition the issuer
    /// is capable and willing to use for credential issuance.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential offer for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`OfferCredentialPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.OfferCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The offer as a JSON object
    async fn vc_zkp_create_credential_offer(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: OfferCredentialPayload = parse!(&payload, "payload");
        let result: CredentialOffer = Issuer::offer_credential(
            &payload.issuer,
            &payload.subject,
            &payload.schema,
            &payload.credential_definition,
        )?;
        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Presents a proof for one or more credentials. A proof presentation is the response to a
    /// proof request. The proof needs to incorporate all required fields from all required schemas
    /// requested in the proof request.
    ///
    /// # Arguments
    ///
    /// * `method` - method to presents a proof for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`PresentProofPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.PresentProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The presentation as a JSON object
    async fn vc_zkp_present_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: PresentProofPayload = parse!(&payload, "payload");

        // Resolve all necessary credential definitions, schemas and registries
        let mut definitions: HashMap<String, CredentialDefinition> = HashMap::new();
        let mut schemas: HashMap<String, CredentialSchema> = HashMap::new();
        let mut revocation_definitions: HashMap<String, RevocationRegistryDefinition> =
            HashMap::new();
        for req in &payload.proof_request.sub_proof_requests {
            let schema_did = &req.schema;
            schemas.insert(
                schema_did.clone(),
                get_document!(&mut self.vade, &schema_did, "schema"),
            );

            let definition_did = payload
                .credentials
                .get(schema_did)
                .ok_or("invalid schema")?
                .proof
                .credential_definition
                .clone();
            definitions.insert(
                schema_did.clone(),
                get_document!(&mut self.vade, &definition_did, "credential definition"),
            );

            // Resolve revocation definition
            let rev_definition_did = payload
                .credentials
                .get(schema_did)
                .ok_or("invalid schema")?
                .proof
                .revocation_registry_definition
                .clone();
            revocation_definitions.insert(
                schema_did.clone(),
                get_document!(&mut self.vade, &rev_definition_did, "revocation definition"),
            );
        }

        let result: ProofPresentation = Prover::present_proof(
            payload.proof_request,
            payload.credentials,
            definitions,
            schemas,
            revocation_definitions,
            payload.witnesses,
            &payload.master_secret,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Creates a new zero-knowledge proof credential proposal. This message is the first in the
    /// credential issuance flow and is sent by the potential credential holder to the credential issuer.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential proposal for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`CreateCredentialProposalPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.CreateCredentialProposalPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The proposal as a JSON object
    async fn vc_zkp_create_credential_proposal(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: CreateCredentialProposalPayload = parse!(&payload, "payload");
        let result: CredentialProposal =
            Prover::propose_credential(&payload.issuer, &payload.subject, &payload.schema);

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Requests a credential. This message is the response to a credential offering and is sent by the potential
    /// credential holder. It incorporates the target schema, credential definition offered by the issuer, and
    /// the encoded values the holder wants to get signed. The credential is not stored on-chain and needs to be
    /// kept private.
    ///
    /// # Arguments
    ///
    /// * `method` - method to request a credential for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`RequestCredentialPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.RequestCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object consisting of the `CredentialRequest` and `CredentialSecretsBlindingFactors` (to be stored at the proofer's site in a private manner)
    async fn vc_zkp_request_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: RequestCredentialPayload = serde_json::from_str(&payload)
            .map_err(|e| format!("{} when parsing payload {}", &e, &payload))?;
        let definition: CredentialDefinition = get_document!(
            &mut self.vade,
            &payload.credential_offering.credential_definition,
            "credential definition"
        );
        let schema: CredentialSchema =
            get_document!(&mut self.vade, &payload.credential_schema, "schema");

        let result = Prover::request_credential(
            payload.credential_offering,
            definition,
            schema,
            payload.master_secret,
            payload.credential_values,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Requests a zero-knowledge proof for one or more credentials issued under one or more specific schemas and
    /// is sent by a verifier to a prover.
    /// The proof request consists of the fields the verifier wants to be revealed per schema.
    ///
    /// # Arguments
    ///
    /// * `method` - method to request a proof for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`RequestProofPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.RequestProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A `ProofRequest` as JSON
    async fn vc_zkp_request_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: RequestProofPayload = parse!(&payload, "payload");
        let result: ProofRequest = Verifier::request_proof(
            &payload.verifier_did,
            &payload.prover_did,
            payload.sub_proof_requests,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Revokes a credential. After revocation the published revocation registry needs to be updated with information
    /// returned by this function. To revoke a credential, tbe revoker must be in possession of the private key associated
    /// with the credential's revocation registry. After revocation, the published revocation registry must be updated.
    /// Only then is the credential truly revoked.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to revoke a credential for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`RevokeCredentialPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.RevokeCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The updated revocation registry definition as a JSON object. Contains information
    /// needed to update the respective revocation registry.
    async fn vc_zkp_revoke_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: RevokeCredentialPayload = parse!(&payload, "payload");
        let rev_def: RevocationRegistryDefinition = get_document!(
            &mut self.vade,
            &payload.revocation_registry_definition,
            "revocation registry definition"
        );

        let updated_registry = Issuer::revoke_credential(
            &payload.issuer,
            &rev_def,
            payload.credential_revocation_id,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized = serde_json::to_string(&updated_registry)?;

        self.set_did_document(
            &rev_def.id,
            &serialized,
            &options.private_key,
            &options.identity,
        )
        .await?;

        Ok(VadePluginResultValue::Success(Some(serialized)))
    }

    /// Verifies one or multiple proofs sent in a proof presentation.
    ///
    /// # Arguments
    ///
    /// * `method` - method to verify a proof for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`ValidateProofPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.ValidateProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object representing a `ProofVerification` type, specifying whether verification was successful
    async fn vc_zkp_verify_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: ValidateProofPayload = parse!(&payload, "payload");

        // Resolve all necessary credential definitions, schemas and registries
        let mut definitions: HashMap<String, CredentialDefinition> = HashMap::new();
        let mut rev_definitions: HashMap<String, Option<RevocationRegistryDefinition>> =
            HashMap::new();
        let mut schemas: HashMap<String, CredentialSchema> = HashMap::new();
        for req in &payload.proof_request.sub_proof_requests {
            let schema_did = &req.schema;
            schemas.insert(
                schema_did.clone(),
                get_document!(&mut self.vade, &schema_did, "schema"),
            );
        }

        for credential in &payload.presented_proof.verifiable_credential {
            let definition_did = &credential.proof.credential_definition.clone();
            definitions.insert(
                credential.credential_schema.id.clone(),
                get_document!(&mut self.vade, definition_did, "credential definition"),
            );

            let rev_definition_did = &credential.proof.revocation_registry_definition.clone();
            rev_definitions.insert(
                credential.credential_schema.id.clone(),
                get_document!(&mut self.vade, &rev_definition_did, "revocation definition"),
            );
        }

        let result: ProofVerification = Verifier::verify_proof(
            payload.presented_proof,
            payload.proof_request,
            definitions,
            schemas,
            rev_definitions,
        );

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }
}
