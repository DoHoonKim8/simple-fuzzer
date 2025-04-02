use evm::Evm;
use fuzzer::{function_selector, SolidityFuzzer};
use revm::primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::process::{Command, Stdio};
use std::{io, str};

pub mod evm;
pub mod fuzzer;

/// --- Solidity Compilation Helpers ---

/// The JSON structure output by solc with --combined-json bin,abi.
#[derive(Deserialize)]
struct ParsedResult {
    contracts: HashMap<String, ParsedContract>,
}

#[derive(Deserialize)]
struct ParsedContract {
    abi: Vec<ParsedFunction>,
    bin: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ParsedFunction {
    name: String,
    inputs: Vec<ParsedParam>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ParsedParam {
    #[serde(rename = "internalType")]
    internal_type: String,
}

pub struct CompilationOutput {
    invariant_checker: (Vec<u8>, Vec<ParsedFunction>),
    target_abi: Vec<ParsedFunction>,
}

/// Compiles Solidity source code (via solc) with optimization and returns both
/// the creation bytecode and ABI. It reads the Solidity source from the provided input.
pub fn compile_solidity(target_name: &str, invariant_checker_name: &str) -> CompilationOutput {
    let process = match Command::new("solc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("--combined-json")
        .arg("bin,abi")
        .arg("-")
        .arg("contract/contract.sol")
        .spawn()
    {
        Ok(process) => process,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            panic!("Command 'solc' not found");
        }
        Err(err) => {
            panic!("Failed to spwan process with command 'solc':\n{err}");
        }
    };
    let output = process.wait_with_output().unwrap();
    let stdout = str::from_utf8(&output.stdout).unwrap();
    let parsed_result: ParsedResult = serde_json::from_str(stdout).unwrap_or_else(|err| {
        panic!(
            "Failed to parse solc JSON output: {err}\nOutput: {}",
            stdout
        )
    });
    let target_name = "contract/contract.sol:".to_string() + target_name;
    let invariant_checker_name = "contract/contract.sol:".to_string() + invariant_checker_name;
    parsed_result
        .contracts
        .get(target_name.as_str())
        .map(|target| {
            parsed_result
                .contracts
                .get(invariant_checker_name.as_str())
                .map(|invariant_checker| CompilationOutput {
                    target_abi: target.abi.to_vec(),
                    invariant_checker: (
                        hex::decode(invariant_checker.bin.as_str())
                            .expect("Invalid hex in contract bytecode"),
                        invariant_checker.abi.to_vec(),
                    ),
                })
                .unwrap_or_else(|| {
                    panic!("Invariant checker not found");
                })
        })
        .unwrap_or_else(|| {
            panic!("Target not found");
        })
}

pub fn deploy_invariant_checker(runner: &mut Evm, bytecode: Vec<u8>) -> Address {
    runner.create(bytecode)
}

pub fn deploy_target(runner: &mut Evm, invariant_checker_address: Address) -> Address {
    let deploy_target_calldata = function_selector("setUp()");
    runner.call(invariant_checker_address, deploy_target_calldata.to_vec());
    let target_calldata = function_selector("inv()");
    let (_, target) = runner.call(invariant_checker_address, target_calldata.to_vec());
    Address::from_slice(&target[12..32])
}

pub fn check_invariant(runner: &mut Evm, invariant_checker_address: Address) -> bool {
    let invariant_check_function_signature = "invariant_neverFalse()";
    let (_, result) = runner.call(
        invariant_checker_address,
        function_selector(invariant_check_function_signature).to_vec(),
    );
    assert_eq!(result.len(), 32);
    // Interpret the last byte of `result` as boolean
    assert_eq!(result[..31], vec![0; 31]);
    result[31] == 1
}

/// Main fuzzer loop.
fn main() {
    // Compile the Solidity source.
    let target_name = "InvariantBreaker";
    let invariant_checker_name = "InvariantTest";
    let output = compile_solidity(target_name, invariant_checker_name);
    let mut runner = Evm::default();
    let invariant_checker_address =
        deploy_invariant_checker(&mut runner, output.invariant_checker.0);
    let target_address = deploy_target(&mut runner, invariant_checker_address);

    let solidity_fuzzer = SolidityFuzzer::new(output.target_abi);
    let mut iterations: u64 = 0;
    loop {
        iterations += 1;
        let calldata = solidity_fuzzer.generate_random_calldata();
        // Run the contract call inside catch_unwind to capture panics.
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            runner.call(target_address, calldata.clone());
        }))
        .and_then(
            |_| match check_invariant(&mut runner, invariant_checker_address) {
                true => Ok(()),
                false => Err(Box::new(())),
            },
        );
        // If a panic is detected, report and exit.
        if result.is_err() {
            println!("Crash found after {} iterations!", iterations);
            println!("Crashing input: {:?}", calldata);
            break;
        }
        // Print progress every 100,000 iterations.
        if iterations % 100_000 == 0 {
            println!("Tested {} iterations without a crash...", iterations);
        }
    }
}
