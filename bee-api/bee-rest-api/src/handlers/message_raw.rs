// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{filters::CustomRejection::NotFound, storage::StorageBackend};

use bee_common::packable::Packable;
use bee_common_pt2::node::ResHandle;
use bee_message::prelude::*;
use bee_protocol::tangle::MsTangle;

use warp::{http::Response, reject, Rejection, Reply};

pub async fn message_raw<B: StorageBackend>(
    message_id: MessageId,
    tangle: ResHandle<MsTangle<B>>,
) -> Result<impl Reply, Rejection> {
    match tangle.get(&message_id).await {
        Some(message) => Ok(Response::builder()
            .header("Content-Type", "application/octet-stream")
            .body(message.pack_new())),
        None => Err(reject::custom(NotFound("can not find message".to_string()))),
    }
}
