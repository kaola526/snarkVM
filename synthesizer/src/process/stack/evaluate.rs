// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

impl<N: Network> StackEvaluate<N> for Stack<N> {
    /// Evaluates a program closure on the given inputs.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    #[inline]
    fn evaluate_closure<A: circuit::Aleo<Network = N>>(
        &self,
        closure: &Closure<N>,
        inputs: &[Value<N>],
        call_stack: CallStack<N>,
        caller: Address<N>,
        tvk: Field<N>,
    ) -> Result<Vec<Value<N>>> {
        let timer = timer!("Stack::evaluate_closure");

        // Ensure the number of inputs matches the number of input statements.
        if closure.inputs().len() != inputs.len() {
            bail!("Expected {} inputs, found {}", closure.inputs().len(), inputs.len())
        }

        // Initialize the registers.
        let mut registers = Registers::<N, A>::new(call_stack, self.get_register_types(closure.name())?.clone());
        // Set the transition caller.
        registers.set_caller(caller);
        // Set the transition view key.
        registers.set_tvk(tvk);
        lap!(timer, "Initialize the registers");

        // Store the inputs.
        closure.inputs().iter().map(|i| i.register()).zip_eq(inputs).try_for_each(|(register, input)| {
            // Assign the input value to the register.
            registers.store(self, register, input.clone())
        })?;
        lap!(timer, "Store the inputs");

        // Evaluate the instructions.
        for instruction in closure.instructions() {
            // If the evaluation fails, bail and return the error.
            if let Err(error) = instruction.evaluate(self, &mut registers) {
                bail!("Failed to evaluate instruction ({instruction}): {error}");
            }
        }
        lap!(timer, "Evaluate the instructions");

        // Load the outputs.
        let outputs = closure
            .outputs()
            .iter()
            .map(|output| {
                match output.operand() {
                    // If the operand is a literal, use the literal directly.
                    Operand::Literal(literal) => Ok(Value::Plaintext(Plaintext::from(literal))),
                    // If the operand is a register, retrieve the stack value from the register.
                    Operand::Register(register) => registers.load(self, &Operand::Register(register.clone())),
                    // If the operand is the program ID, convert the program ID into an address.
                    Operand::ProgramID(program_id) => {
                        Ok(Value::Plaintext(Plaintext::from(Literal::Address(program_id.to_address()?))))
                    }
                    // If the operand is the caller, retrieve the caller from the registers.
                    Operand::Caller => Ok(Value::Plaintext(Plaintext::from(Literal::Address(registers.caller()?)))),
                }
            })
            .collect();
        lap!(timer, "Load the outputs");

        finish!(timer);
        outputs
    }

    /// Evaluates a program function on the given inputs.
    ///
    /// # Errors
    /// This method will halt if the given inputs are not the same length as the input statements.
    #[inline]
    fn evaluate_function<A: circuit::Aleo<Network = N>>(&self, call_stack: CallStack<N>) -> Result<Response<N>> {
        let timer = timer!("Stack::evaluate_function");
        web_sys::console::time_stamp_with_data(&"evaluate_function".into());
        web_sys::console::time_with_label("evaluate_function");
        // Retrieve the next request, based on the call stack mode.
        let (request, call_stack) = match &call_stack {
            CallStack::Evaluate(authorization) => (authorization.next()?, call_stack),
            CallStack::Execute(authorization, ..) => (authorization.peek_next()?, call_stack.replicate()),
            _ => bail!("Illegal operation: call stack must be `Evaluate` or `Execute` in `evaluate_function`."),
        };
        lap!(timer, "Retrieve the next request");
        web_sys::console::time_end_with_label("evaluate_function");
        web_sys::console::time_stamp_with_data(&"Retrieve the next request".into());
        web_sys::console::time_with_label("Retrieve the next request");

        // Ensure the network ID matches.
        ensure!(
            **request.network_id() == N::ID,
            "Network ID mismatch. Expected {}, but found {}",
            N::ID,
            request.network_id()
        );

        // Retrieve the function, inputs, and transition view key.
        let function = self.get_function(request.function_name())?;
        let inputs = request.inputs();
        let caller = *request.caller();
        let tvk = *request.tvk();

        // Ensure the number of inputs matches.
        if function.inputs().len() != inputs.len() {
            bail!(
                "Function '{}' in the program '{}' expects {} inputs, but {} were provided.",
                function.name(),
                self.program.id(),
                function.inputs().len(),
                inputs.len()
            )
        }
        lap!(timer, "Perform input checks");
        web_sys::console::time_end_with_label("Retrieve the next request");
        web_sys::console::time_stamp_with_data(&"Perform input checks".into());
        web_sys::console::time_with_label("Perform input checks");

        // Initialize the registers.
        let mut registers = Registers::<N, A>::new(call_stack, self.get_register_types(function.name())?.clone());
        // Set the transition caller.
        registers.set_caller(caller);
        // Set the transition view key.
        registers.set_tvk(tvk);
        lap!(timer, "Initialize the registers");
        web_sys::console::time_end_with_label("Perform input checks");
        web_sys::console::time_stamp_with_data(&"Initialize the registers".into());
        web_sys::console::time_with_label("Initialize the registers");

        // Ensure the request is well-formed.
        ensure!(request.verify(&function.input_types()), "Request is invalid");
        lap!(timer, "Verify the request");
        web_sys::console::time_end_with_label("Initialize the registers");
        web_sys::console::time_stamp_with_data(&"Verify the request".into());
        web_sys::console::time_with_label("Verify the request");

        // Store the inputs.
        function.inputs().iter().map(|i| i.register()).zip_eq(inputs).try_for_each(|(register, input)| {
            // Assign the input value to the register.
            registers.store(self, register, input.clone())
        })?;
        lap!(timer, "Store the inputs");
        web_sys::console::time_end_with_label("Verify the request");
        web_sys::console::time_stamp_with_data(&"Store the inputs".into());
        web_sys::console::time_with_label("Store the inputs");

        // Evaluate the instructions.
        for instruction in function.instructions() {
            // If the evaluation fails, bail and return the error.
            if let Err(error) = instruction.evaluate(self, &mut registers) {
                bail!("Failed to evaluate instruction ({instruction}): {error}");
            }
        }
        lap!(timer, "Evaluate the instructions");
        web_sys::console::time_end_with_label("Store the inputs");
        web_sys::console::time_stamp_with_data(&"Evaluate the instructions".into());
        web_sys::console::time_with_label("Evaluate the instructions");

        // Retrieve the output operands.
        let output_operands = &function.outputs().iter().map(|output| output.operand()).collect::<Vec<_>>();
        lap!(timer, "Retrieve the output operands");
        web_sys::console::time_end_with_label("Evaluate the instructions");
        web_sys::console::time_stamp_with_data(&"Retrieve the output operands".into());
        web_sys::console::time_with_label("Retrieve the output operands");

        // Load the outputs.
        let outputs = output_operands
            .iter()
            .map(|operand| {
                match operand {
                    // If the operand is a literal, use the literal directly.
                    Operand::Literal(literal) => Ok(Value::Plaintext(Plaintext::from(literal))),
                    // If the operand is a register, retrieve the stack value from the register.
                    Operand::Register(register) => registers.load(self, &Operand::Register(register.clone())),
                    // If the operand is the program ID, convert the program ID into an address.
                    Operand::ProgramID(program_id) => {
                        Ok(Value::Plaintext(Plaintext::from(Literal::Address(program_id.to_address()?))))
                    }
                    // If the operand is the caller, retrieve the caller from the registers.
                    Operand::Caller => Ok(Value::Plaintext(Plaintext::from(Literal::Address(registers.caller()?)))),
                }
            })
            .collect::<Result<Vec<_>>>()?;
        lap!(timer, "Load the outputs");
        web_sys::console::time_end_with_label("Retrieve the output operands");

        finish!(timer);

        // Map the output operands to registers.
        let output_registers = output_operands
            .iter()
            .map(|operand| match operand {
                Operand::Register(register) => Some(register.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        // Compute the response.
        Response::new(
            request.network_id(),
            self.program.id(),
            function.name(),
            request.inputs().len(),
            request.tvk(),
            request.tcm(),
            outputs,
            &function.output_types(),
            &output_registers,
        )
    }
}
