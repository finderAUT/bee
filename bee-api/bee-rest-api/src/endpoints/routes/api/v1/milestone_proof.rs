// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use crate::{
    endpoints::{
        config::ROUTE_MILESTONE, filters::with_tangle, path_params::milestone_index, permission::has_permission,
        rejection::CustomRejection, storage::StorageBackend,
    },
    types::{body::SuccessBody, responses::MilestoneResponse},
};

use bee_message::milestone::MilestoneIndex;
use bee_runtime::resource::ResourceHandle;
use bee_tangle::Tangle;

use warp::{filters::BoxedFilter, reject, Filter, Rejection, Reply};

use std::net::IpAddr;
use bee_ledger::workers::consensus;
use bee_ledger::workers::consensus::WhiteFlagMetadata;
use bee_ledger::workers::error::Error;
use bee_message::MessageId;
use crate::endpoints::path_params::message_id;
use crate::types::responses::MilestoneProofResponse;

fn path() -> impl Filter<Extract = (MilestoneIndex,), Error = Rejection> + Clone {
    super::path()
        .and(warp::path("milestones"))
        .and(milestone_index())
        .and(warp::path("proof"))
        .and(message_id())
        .and(warp::path::end())
}

pub(crate) fn filter<B: StorageBackend>(
    public_routes: Box<[String]>,
    allowed_ips: Box<[IpAddr]>,
    tangle: ResourceHandle<Tangle<B>>,
) -> BoxedFilter<(impl Reply,)> {
    self::path()
        .and(warp::get())
        .and(has_permission(ROUTE_MILESTONE, public_routes, allowed_ips))
        .and(with_tangle(tangle))
        .and_then(milestone_proof)
        .boxed()
}

pub(crate) async fn milestone_proof<B: StorageBackend>(
    milestone_index: MilestoneIndex,
    tangle: ResourceHandle<Tangle<B>>,
) -> Result<impl Reply, Rejection> {
    match tangle.get_milestone_message(milestone_index).await {
        Some(milestone_message) => {
            let mut metadata = WhiteFlagMetadata::new(index);
            rebuild_included_messages(tangle, storage, milestone_message.parents().iter().rev().copied().collect(), &mut metadata).await?;
            println!("{:?}", metadata.included_messages());

            Ok(warp::reply::json(&SuccessBody::new(MilestoneProofResponse {
                milestone_index: *milestone_index,
                included_messages: metadata.included_messages().iter().map(|msg| msg.to_string()).collect()
            })))
        },
        None => Err(reject::custom(CustomRejection::NotFound(
            "can not find milestone".to_string(),
        ))),
    }
}

async fn rebuild_included_messages<B: StorageBackend>(
    tangle: ResourceHandle<Tangle<B>>,
    storage: &B,
    mut message_ids: Vec<MessageId>,
    metadata: &mut WhiteFlagMetadata,
) -> Result<(), Error> {
    let mut visited = HashSet::new();
    while let Some(message_id) = message_ids.last() {
        if let Some((message, meta)) = tangle
            .get_vertex(message_id)
            .await
            .as_ref()
            .and_then(|v| v.message_and_metadata().cloned())
        {
            if meta.milestone_index() != metadata.index() {
                visited.insert(*message_id);
                message_ids.pop();
                continue;
            }

            if let Some(unvisited) = message.parents().iter()
                .find(|p| !visited.contains(p)) {
                message_ids.push(*unvisited);
            } else {
                apply_message(storage, message_id, &message, metadata)?;
                visited.insert(*message_id);
                message_ids.pop();
            }
        } else if !tangle.is_solid_entry_point(message_id).await {
            return Err(Error::MissingMessage(*message_id));
        } else {
            visited.insert(*message_id);
            message_ids.pop();
        }
    }

    Ok(())
}
