// Copyright (C) 2019-2021 Aleo Systems Inc.
// This file is part of the snarkVM library.

// The snarkVM library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The snarkVM library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the snarkVM library. If not, see <https://www.gnu.org/licenses/>.

use crate::{Address, DPCError, Network, Payload, Record, RecordScheme, ViewKey};
use snarkvm_algorithms::{
    merkle_tree::MerkleTreeDigest,
    traits::{CommitmentScheme, EncryptionScheme, CRH},
};
use snarkvm_utilities::{
    io::{Cursor, Result as IoResult},
    marker::PhantomData,
    FromBytes,
    Read,
    ToBytes,
    Write,
};

use rand::{thread_rng, CryptoRng, Rng};

#[derive(Derivative)]
#[derivative(
    Clone(bound = "N: Network"),
    Debug(bound = "N: Network"),
    PartialEq(bound = "N: Network"),
    Eq(bound = "N: Network")
)]
pub struct EncryptedRecord<N: Network> {
    ciphertext: Vec<u8>,
    phantom: PhantomData<N>,
}

impl<N: Network> EncryptedRecord<N> {
    pub fn new(ciphertext: Vec<u8>) -> Self {
        Self {
            ciphertext,
            phantom: PhantomData,
        }
    }

    /// Encrypt the given vector of records and returns
    /// 1. Encrypted record
    /// 2. Encryption randomness
    pub fn encrypt<R: Rng + CryptoRng>(
        record: &Record<N>,
        rng: &mut R,
    ) -> Result<
        (
            Self,
            <<N as Network>::AccountEncryptionScheme as EncryptionScheme>::Randomness,
        ),
        DPCError,
    > {
        // Serialize the record into bytes
        let mut bytes = vec![];

        // Program ID
        let program_id = record.program_id();
        bytes.extend_from_slice(&program_id.to_bytes_le()?);

        // Value
        let value = record.value();
        bytes.extend_from_slice(&value.to_bytes_le()?);

        // Payload
        let payload = record.payload();
        bytes.extend_from_slice(&payload.to_bytes_le()?);

        // Serial number nonce
        let serial_number_nonce = record.serial_number_nonce();
        bytes.extend_from_slice(&serial_number_nonce.to_bytes_le()?);

        // Commitment randomness
        let commitment_randomness = record.commitment_randomness();
        bytes.extend_from_slice(&commitment_randomness.to_bytes_le()?);

        assert!(
            bytes.len() <= u16::MAX as usize,
            "The DPC assumes that the record is less than 65535 bytes."
        );

        // Encrypt the record plaintext.
        let encryption_key = record.owner().encryption_key();
        let encryption_randomness = N::account_encryption_scheme().generate_randomness(&encryption_key, rng)?;
        let encrypted_record =
            N::account_encryption_scheme().encrypt(&encryption_key, &encryption_randomness, &bytes)?;
        let encrypted_record = Self::new(encrypted_record);

        Ok((encrypted_record, encryption_randomness))
    }

    /// Decrypt and reconstruct the encrypted record.
    pub fn decrypt(&self, account_view_key: &ViewKey<N>) -> Result<Record<N>, DPCError> {
        // Decrypt the encrypted record
        let plaintext = N::account_encryption_scheme().decrypt(&*account_view_key, &self.ciphertext)?;

        let mut cursor = Cursor::new(plaintext);

        // Program ID
        let program_id: MerkleTreeDigest<N::ProgramCircuitTreeParameters> = FromBytes::read_le(&mut cursor)?;

        // Value
        let value = u64::read_le(&mut cursor)?;

        // Payload
        let payload = Payload::read_le(&mut cursor)?;

        // Serial number nonce
        let serial_number_nonce = N::SerialNumberNonce::read_le(&mut cursor)?;

        // Commitment randomness
        let commitment_randomness = <N::CommitmentScheme as CommitmentScheme>::Randomness::read_le(&mut cursor)?;

        // Construct the record account address
        let owner = Address::from_view_key(&account_view_key)?;

        // Determine if the record is a dummy
        // TODO (raychu86) Establish `is_dummy` flag properly by checking that the value is 0 and the programs are equivalent to a global dummy
        let dummy_program = program_id.clone();
        let is_dummy = (value == 0) && (payload == Payload::default()) && (program_id == dummy_program);

        Ok(Record::from(
            program_id,
            owner,
            is_dummy,
            value,
            payload,
            serial_number_nonce,
            commitment_randomness,
        )?)
    }

    /// Returns the encrypted record hash.
    /// The hash input is the ciphertext x-coordinates appended with the selector bits.
    pub fn to_hash(&self) -> Result<<<N as Network>::EncryptedRecordCRH as CRH>::Output, DPCError> {
        Ok(N::encrypted_record_crh().hash(&self.ciphertext)?)
    }
}

impl<N: Network> Default for EncryptedRecord<N> {
    fn default() -> Self {
        let (record, _randomness) = Self::encrypt(&Record::default(), &mut thread_rng()).unwrap();
        record
    }
}

impl<N: Network> ToBytes for EncryptedRecord<N> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (self.ciphertext.len() as u16).write_le(&mut writer)?;
        self.ciphertext.write_le(&mut writer)
    }
}

impl<N: Network> FromBytes for EncryptedRecord<N> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let ciphertext_len = u16::read_le(&mut reader)?;
        let mut ciphertext = Vec::with_capacity(ciphertext_len as usize);
        for _ in 0..ciphertext_len {
            ciphertext.push(u8::read_le(&mut reader)?);
        }

        Ok(Self::new(ciphertext))
    }
}