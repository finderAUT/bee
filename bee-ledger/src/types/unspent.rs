// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::types::error::Error;

use bee_common::packable::{Packable, Read, Write};
use bee_message::output::OutputId;

use std::ops::Deref;

/// Represents an output id as unspent.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct Unspent(OutputId);

impl From<OutputId> for Unspent {
    fn from(id: OutputId) -> Self {
        Unspent(id)
    }
}

impl Deref for Unspent {
    type Target = OutputId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Unspent {
    /// Creates a new `Unspent`.
    pub fn new(output_id: OutputId) -> Self {
        output_id.into()
    }

    /// Returns the identifier of an `Unspent`.
    pub fn id(&self) -> &OutputId {
        &self.0
    }
}

impl core::fmt::Display for Unspent {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", *self)
    }
}

impl core::fmt::Debug for Unspent {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Unspent({})", self)
    }
}

impl Packable for Unspent {
    type Error = Error;

    fn packed_len(&self) -> usize {
        self.0.packed_len()
    }

    fn pack<W: Write>(&self, writer: &mut W) -> Result<(), Self::Error> {
        self.0.pack(writer)?;

        Ok(())
    }

    fn unpack_inner<R: Read + ?Sized, const CHECK: bool>(reader: &mut R) -> Result<Self, Self::Error> {
        Ok(Self(OutputId::unpack_inner::<R, CHECK>(reader)?))
    }
}
