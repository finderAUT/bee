// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;
use std::ops::Deref;
use crypto::hashes::blake2b::Blake2b256;
use digest::{Digest, Update};
use rs_merkle::MerkleTree;
use rs_merkle::utils::collections::to_hex_string;
use bee_message::MessageId;
use bee_runtime::resource::ResourceHandle;
use bee_tangle::Tangle;
use warp::{filters::BoxedFilter, reject, Filter, Rejection, Reply};
use bee_message::payload::Payload;

use crate::{
    endpoints::{
        config::ROUTE_MESSAGE, filters::with_tangle, path_params::message_id, permission::has_permission,
        rejection::CustomRejection, storage::StorageBackend,
    },
    types::{body::SuccessBody, dtos::MessageDto, responses::MessageResponse},
};
use crate::endpoints::routes::api::v1::milestone_included_messages::rebuild_included_messages;
use crate::types::responses::MessageProofResponse;

fn path() -> impl Filter<Extract = (MessageId,), Error = Rejection> + Clone {
    super::path()
        .and(warp::path("messages"))
        .and(message_id())
        .and(warp::path("proof"))
        .and(warp::path::end())
}

pub(crate) fn filter<B: StorageBackend>(
    public_routes: Box<[String]>,
    allowed_ips: Box<[IpAddr]>,
    tangle: ResourceHandle<Tangle<B>>,
) -> BoxedFilter<(impl Reply,)> {
    self::path()
        .and(warp::get())
        .and(has_permission(ROUTE_MESSAGE, public_routes, allowed_ips))
        .and(with_tangle(tangle))
        .and_then(|message_id, tangle| async move { message_proof(message_id, tangle) })
        .boxed()
}

pub(crate) fn message_proof<B: StorageBackend>(
    message_id: MessageId,
    tangle: ResourceHandle<Tangle<B>>,
) -> Result<impl Reply, Rejection> {
    match tangle.get_message_and_metadata(&message_id) {
        Some((message, meta)) => {
            let milestone_index = meta.milestone_index().expect("No milestone index in message meta data");;
            let milestone_message = tangle.get_milestone_message(milestone_index).expect("No milestone found");

            let milestone_payload = match milestone_message.payload() {
                Some(Payload::Milestone(milestone)) => milestone,
                _ => Err(reject::custom(CustomRejection::NotFound(
                    "can not find message".to_string(),
                )))
            };
            milestone_payload.essence().merkle_proof();

            let mut included_messages = Vec::new();
            let parents_message_ids = Deref::deref(milestone_message.parents());
            rebuild_included_messages(tangle, milestone_index, parents_message_ids.iter().rev().copied().collect(), &mut included_messages)
                .await
                .map_err(|e| reject::custom(CustomRejection::BadRequest(e.to_string())))?;

            create_leaves_from_hex(included_messages);
            let merkle_tree = MerkleTree::<BlakeAlgo>::from_leaves(&leaves);
            let proof_index = included_messages.iter().position(|&x| x == message_id).unwrap();
            let indices_to_prove = vec![proof_index];
            let merkle_proof = merkle_tree.proof(&indices_to_prove);
            let proof_bytes = merkle_proof.to_bytes(); //same as merkle_proof.serialize::<DirectHashesOrder>();
            let merkle_root = merkle_tree.root().expect("couldn't get the merkle root");

            assert!(merkle_root.eq(milestone_payload.essence().merkle_proof()));

            Ok(warp::reply::json(&SuccessBody::new(MessageProofResponse(
                *milestone_index,
                MessageDto::from(&message,),
                proof_index,
                base64::encode(proof_bytes)
            ))))
        },
        None => Err(reject::custom(CustomRejection::NotFound(
            "can not find message".to_string(),
        ))),
    }
}

const LEAF_HASH_PREFIX: u8 = 0x00;
const NODE_HASH_PREFIX: u8 = 0x01;

#[derive(Clone)]
pub struct BlakeAlgo {}

impl rs_merkle::Hasher for BlakeAlgo {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2b256::new();

        hasher.update(data);
        <Self::Hash>::from(hasher.finalize())
    }

    //does not use Self:hash anymore
    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {

        match right {
            Some(right_node) => {
                let mut hasher = Blake2b256::new_with_prefix([NODE_HASH_PREFIX]);
                hasher.update(left);
                hasher.update(right_node);
                let hash = <Self::Hash>::from(hasher.finalize());
                println!("node {}", to_hex_string(&hash));
                hash
            }
            None =>  {
                *left
            },
        }
    }
}

pub fn create_leaves_from_hex(input: Vec<MessageId>) -> Vec<[u8; 32]> {
    /*let leaf_values = vec!("52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649",
                           "81855ad8681d0d86d1e91e00167939cb6694d2c422acd208a0072939487f6999",
                           "eb9d18a44784045d87f3c67cf22746e995af5a25367951baa2ff6cd471c483f1",
                           "5fb90badb37c5821b6d95526a41a9504680b4e7c8b763a1b1d49d4955c848621",
                           "6325253fec738dd7a9e28bf921119c160f0702448615bbda08313f6a8eb668d2",
                           "0bf5059875921e668a5bdf2c7fc4844592d2572bcd0668d2d6c52f5054e2d083",
                           "6bf84c7174cb7476364cc3dbd968b0f7172ed85794bb358b0c3b525da1786f9f"
    );*/
    let x = input
        .iter()
        .map(|message_id| message_id.as_ref())
        .map(|bytes| {
            let mut hasher = Blake2b256::new();
            hasher.update([LEAF_HASH_PREFIX]);
            hasher.update(bytes);
            <[u8; 32]>::from(hasher.finalize())
        })
        .collect::<Vec<[u8; 32]>>();
    return x
}
