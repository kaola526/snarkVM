// Copyright (C) 2019-2022 Aleo Systems Inc.
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

pub mod add;
pub use add::*;

pub mod div;
pub use div::*;

pub mod double;
pub use double::*;

pub mod equal;
pub use equal::*;

pub mod gt;
pub use gt::*;

pub mod gte;
pub use gte::*;

pub mod inv;
pub use inv::*;

pub mod lt;
pub use lt::*;

pub mod lte;
pub use lte::*;

pub mod mul;
pub use mul::*;

pub mod neg;
pub use neg::*;

pub mod neq;
pub use neq::*;

pub mod pow;
pub use pow::*;

pub mod square;
pub use square::*;

pub mod sub;
pub use sub::*;

pub mod ternary;
pub use ternary::*;

use crate::{Memory, Operation, Sanitizer};
use snarkvm_circuits::ParserResult;
use snarkvm_utilities::{error, FromBytes, ToBytes};

use core::fmt;
use enum_index::EnumIndex;
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::map,
    sequence::{pair, preceded},
};
use std::io::{Read, Result as IoResult, Write};

// TODO (@pranav) There appears to be a bug with IndexEnum when applying the proc macro to parse
//  the below enum variants. The issue may be related to the use of type parameters in enum
//  variants as the error reports: comparison operators cannot be chained.
#[derive(EnumIndex)]
pub enum Instruction<M: Memory> {
    /// Adds `first` with `second`, storing the outcome in `destination`.
    Add(Add<M>),
    /// Divides `first` with `second`, storing the outcome in `destination`.
    Div(Div<M>),
    /// Doubles `operand`, storing the outcome in `destination`.
    Double(Double<M>),
    /// Checks that `first` is equal to `second`, storing the outcome in `destination`.
    Equal(Equal<M>),
    /// Checks that `first` is greater than `second`, storing the outcome in `destination`.
    GreaterThan(GreaterThan<M>),
    /// Checks that `first` is greater than or equal to `second`, storing the outcome in `destination`.
    GreaterThanOrEqual(GreaterThanOrEqual<M>),
    /// Computes the multiplicative inverse of `operand`, storing the outcome in `destination`.
    Inv(Inv<M>),
    /// Checks that `first` is less than `second`, storing the outcome in `destination`.
    LessThan(LessThan<M>),
    /// Checks that `first` is less than or equal to `second`, storing the outcome in `destination`.
    LessThanOrEqual(LessThanOrEqual<M>),
    /// Multiplies `first` with `second`, storing the outcome in `destination`.
    Mul(Mul<M>),
    /// Negates `operand`, storing the outcome in `destination`.
    Neg(Neg<M>),
    /// Checks that `first` is not equal to `second`, storing the outcome in `destination`.
    NotEqual(NotEqual<M>),
    /// Exponentiates `first` by `second`, storing the outcome in `destination`.
    Pow(Pow<M>),
    /// Squares `operand`, storing the outcome in `destination`.
    Square(Square<M>),
    /// Subtracts `first` from `second`, storing the outcome in `destination`.
    Sub(Sub<M>),
    /// Selects `first`, if `condition` is true, otherwise selects `second`, storing the result in `destination`.
    Ternary(Ternary<M>),
}

impl<M: Memory> Instruction<M> {
    /// Returns the opcode for the instruction
    #[inline]
    pub(crate) fn opcode(&self) -> u16 {
        self.enum_index() as u16
    }

    /// Returns the mnemonic for the instruction.
    #[inline]
    pub(crate) fn mnemonic(&self) -> &'static str {
        match self {
            Self::Add(..) => Add::<M>::mnemonic(),
            Self::Div(..) => Div::<M>::mnemonic(),
            Self::Double(..) => Double::<M>::mnemonic(),
            Self::Equal(..) => Equal::<M>::mnemonic(),
            Self::GreaterThan(..) => GreaterThan::<M>::mnemonic(),
            Self::GreaterThanOrEqual(..) => GreaterThanOrEqual::<M>::mnemonic(),
            Self::Inv(..) => Inv::<M>::mnemonic(),
            Self::LessThan(..) => LessThan::<M>::mnemonic(),
            Self::LessThanOrEqual(..) => LessThanOrEqual::<M>::mnemonic(),
            Self::Mul(..) => Mul::<M>::mnemonic(),
            Self::Neg(..) => Neg::<M>::mnemonic(),
            Self::NotEqual(..) => NotEqual::<M>::mnemonic(),
            Self::Pow(..) => Pow::<M>::mnemonic(),
            Self::Square(..) => Square::<M>::mnemonic(),
            Self::Sub(..) => Sub::<M>::mnemonic(),
            Self::Ternary(..) => Ternary::<M>::mnemonic(),
        }
    }

    /// Evaluates the instruction.
    #[inline]
    pub(crate) fn evaluate(&self, memory: &M) {
        match self {
            Self::Add(instruction) => instruction.evaluate(memory),
            Self::Div(instruction) => instruction.evaluate(memory),
            Self::Double(instruction) => instruction.evaluate(memory),
            Self::Equal(instruction) => instruction.evaluate(memory),
            Self::GreaterThan(instruction) => instruction.evaluate(memory),
            Self::GreaterThanOrEqual(instruction) => instruction.evaluate(memory),
            Self::Inv(instruction) => instruction.evaluate(memory),
            Self::LessThan(instruction) => instruction.evaluate(memory),
            Self::LessThanOrEqual(instruction) => instruction.evaluate(memory),
            Self::Mul(instruction) => instruction.evaluate(memory),
            Self::Neg(instruction) => instruction.evaluate(memory),
            Self::NotEqual(instruction) => instruction.evaluate(memory),
            Self::Pow(instruction) => instruction.evaluate(memory),
            Self::Square(instruction) => instruction.evaluate(memory),
            Self::Sub(instruction) => instruction.evaluate(memory),
            Self::Ternary(instruction) => instruction.evaluate(memory),
        }
    }

    /// Parses a string into an instruction.
    #[inline]
    pub(crate) fn parse(string: &str, memory: M) -> ParserResult<Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the instruction from the string.
        let (string, instruction) = alt((
            // Note that order of the individual parsers matters.
            preceded(pair(tag(Add::<M>::mnemonic()), tag(" ")), map(|s| Add::parse(s, memory.clone()), Into::into)),
            preceded(pair(tag(Sub::<M>::mnemonic()), tag(" ")), map(|s| Sub::parse(s, memory.clone()), Into::into)),
        ))(string)?;

        // Parse the semicolon from the string.
        let (string, _) = tag(";")(string)?;

        Ok((string, instruction))
    }
}

impl<M: Memory> fmt::Display for Instruction<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Add(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::Div(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::Double(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::Equal(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::GreaterThan(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::GreaterThanOrEqual(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::Inv(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::LessThan(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::LessThanOrEqual(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::Mul(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::Neg(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::NotEqual(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::Pow(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::Square(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::Sub(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
            Self::Ternary(instruction) => write!(f, "{} {};", self.mnemonic(), instruction),
        }
    }
}

// TODO (@pranav) Hard coding constants is not maintainable.
impl<M: Memory> FromBytes for Instruction<M> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        match u16::read_le(&mut reader) {
            Ok(0) => Ok(Self::Add(Add::read_le(&mut reader)?)),
            Ok(1) => Ok(Self::Div(Div::read_le(&mut reader)?)),
            Ok(2) => Ok(Self::Double(Double::read_le(&mut reader)?)),
            Ok(3) => Ok(Self::Equal(Equal::read_le(&mut reader)?)),
            Ok(4) => Ok(Self::GreaterThan(GreaterThan::read_le(&mut reader)?)),
            Ok(5) => Ok(Self::GreaterThanOrEqual(GreaterThanOrEqual::read_le(&mut reader)?)),
            Ok(6) => Ok(Self::Inv(Inv::read_le(&mut reader)?)),
            Ok(7) => Ok(Self::LessThan(LessThan::read_le(&mut reader)?)),
            Ok(8) => Ok(Self::LessThanOrEqual(LessThanOrEqual::read_le(&mut reader)?)),
            Ok(9) => Ok(Self::Mul(Mul::read_le(&mut reader)?)),
            Ok(10) => Ok(Self::Neg(Neg::read_le(&mut reader)?)),
            Ok(11) => Ok(Self::NotEqual(NotEqual::read_le(&mut reader)?)),
            Ok(12) => Ok(Self::Pow(Pow::read_le(&mut reader)?)),
            Ok(13) => Ok(Self::Square(Square::read_le(&mut reader)?)),
            Ok(14) => Ok(Self::Sub(Sub::read_le(&mut reader)?)),
            Ok(15) => Ok(Self::Ternary(Ternary::read_le(&mut reader)?)),
            Ok(code) => Err(error(format!("FromBytes failed to parse an instruction of code {code}"))),
            Err(err) => Err(err),
        }
    }
}

impl<M: Memory> ToBytes for Instruction<M> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.opcode().write_le(&mut writer)?;
        match self {
            Instruction::Add(instruction) => instruction.write_le(&mut writer),
            Instruction::Div(instruction) => instruction.write_le(&mut writer),
            Instruction::Double(instruction) => instruction.write_le(&mut writer),
            Instruction::Equal(instruction) => instruction.write_le(&mut writer),
            Instruction::GreaterThan(instruction) => instruction.write_le(&mut writer),
            Instruction::GreaterThanOrEqual(instruction) => instruction.write_le(&mut writer),
            Instruction::Inv(instruction) => instruction.write_le(&mut writer),
            Instruction::LessThan(instruction) => instruction.write_le(&mut writer),
            Instruction::LessThanOrEqual(instruction) => instruction.write_le(&mut writer),
            Instruction::Mul(instruction) => instruction.write_le(&mut writer),
            Instruction::Neg(instruction) => instruction.write_le(&mut writer),
            Instruction::NotEqual(instruction) => instruction.write_le(&mut writer),
            Instruction::Pow(instruction) => instruction.write_le(&mut writer),
            Instruction::Square(instruction) => instruction.write_le(&mut writer),
            Instruction::Sub(instruction) => instruction.write_le(&mut writer),
            Instruction::Ternary(instruction) => instruction.write_le(&mut writer),
        }
    }
}
