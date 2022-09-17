// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use crate::{
    endpoints::{
        config::ROUTE_MILESTONE, filters::with_tangle, path_params::milestone_index, permission::has_permission,
        rejection::CustomRejection, storage::StorageBackend,
    },
    types::{body::SuccessBody, responses::MilestoneProofResponse},
};

use bee_message::milestone::MilestoneIndex;
use bee_runtime::resource::ResourceHandle;
use bee_tangle::{ConflictReason, Tangle};

use warp::{filters::BoxedFilter, reject, Filter, Rejection, Reply};

use std::net::IpAddr;
use std::ops::Deref;
use bee_ledger::{
    workers::error::Error
};
use bee_message::MessageId;
use bee_message::payload::Payload;

fn path() -> impl Filter<Extract = (MilestoneIndex,), Error = Rejection> + Clone {
    super::path()
        .and(warp::path("milestones"))
        .and(milestone_index())
        .and(warp::path("included-messages"))
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
        .and_then(milestone_included_messages)
        .boxed()
}

pub(crate) async fn milestone_included_messages<B: StorageBackend>(
    milestone_index: MilestoneIndex,
    tangle: ResourceHandle<Tangle<B>>,
) -> Result<impl Reply, Rejection> {
    match tangle.get_milestone_message(milestone_index) {
        Some(milestone_message) => {
            let mut included_messages = Vec::new();
            // get &[MessageId] from &Parent as it is needed like that to use iter().rev()
            let parents_message_ids = Deref::deref(milestone_message.parents());
            rebuild_included_messages(tangle, milestone_index, parents_message_ids.iter().rev().copied().collect(), &mut included_messages)
                .await
                .map_err(|e| reject::custom(CustomRejection::BadRequest(e.to_string())))?;
            println!("{:?}", included_messages);

            Ok(warp::reply::json(&SuccessBody::new(MilestoneProofResponse {
                milestone_index: *milestone_index,
                included_messages: included_messages.iter().map(|msg| msg.to_string()).collect()
            })))
        },
        None => Err(reject::custom(CustomRejection::NotFound(
            "can not find milestone".to_string(),
        ))),
    }
}

pub(crate) async fn rebuild_included_messages<B: StorageBackend>(
    tangle: ResourceHandle<Tangle<B>>,
    milestone_index: MilestoneIndex,
    mut message_ids: Vec<MessageId>,
    included_messages: &mut Vec<MessageId>, //placement of mut / &mut in function params https://users.rust-lang.org/t/solved-placement-of-mut-in-function-parameters/19891/2
) -> Result<(), Error> {
    let mut visited = HashSet::new();
    while let Some(message_id) = message_ids.last() {
        if let Some((message, meta)) = tangle.get_message_and_metadata(message_id)
        {
            //TODO best way to compare Option with value?
            if meta.milestone_index() != Some(milestone_index) {
                visited.insert(*message_id);
                message_ids.pop();
                continue;
            }

            if let Some(unvisited) = message.parents().iter()
                .find(|p| !visited.contains(p)) {
                message_ids.push(*unvisited);
            } else {
                //see consensus/whiteflag apply_message and consensus/worker.rs for each in loops
                if meta.conflict() == ConflictReason::None
                    && meta.flags().is_solid()
                {
                    //Rust if let syntax / pattern matching https://www.seventeencups.net/posts/why-if-let/
                    //https://users.rust-lang.org/t/i-have-a-hard-time-understanding-the-if-let-syntax/48816/12
                    if let Some(Payload::Transaction(_transaction)) = message.payload() {
                        included_messages.push(*message_id);
                    }
                }
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
