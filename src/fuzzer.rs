use itertools::Itertools;
use rand::Rng;
use tiny_keccak::{Hasher, Keccak};

use crate::ParsedFunction;

#[derive(Debug, Clone)]
enum ParamKind {
    /// Address.
    Address,
    /// Bytes.
    Bytes,
    /// Signed integer.
    Int(usize),
    /// Unsigned integer.
    Uint(usize),
    /// Boolean.
    Bool,
    /// String.
    String,
    /// Array of unknown size.
    Array(Box<ParamKind>),
    /// Vector of bytes with fixed size.
    FixedBytes(usize),
    /// Array with fixed size.
    FixedArray(Box<ParamKind>, usize),
    /// Tuple containing different types
    Tuple(Vec<ParamKind>),
}

impl ParamKind {
    fn from_string(str: &str) -> Self {
        match str {
            "address" => Self::Address,
            "bytes" => Self::Bytes,
            "uint8" => Self::Uint(8),
            _ => unimplemented!(),
        }
    }

    fn random(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        match &self {
            ParamKind::Uint(8) => {
                let r: u8 = rng.gen_range(0..=255);
                let mut output = vec![0u8; 31];
                output.append(&mut r.to_be_bytes().to_vec());
                output
            }
            ParamKind::Int(_)
            | ParamKind::Address
            | ParamKind::Bytes
            | ParamKind::Uint(_)
            | ParamKind::Bool
            | ParamKind::String
            | ParamKind::Array(_)
            | ParamKind::FixedBytes(_)
            | ParamKind::FixedArray(_, _)
            | ParamKind::Tuple(_) => unimplemented!(),
        }
    }
}

/// Structure holding a function's signature information.
#[derive(Debug, Clone)]
struct FunctionSpec {
    /// 4-byte function selector.
    selector: [u8; 4],
    /// Parameter types for this function.
    params: Vec<ParamKind>,
    name: String,
}

/// --- Fuzzer Infrastructure ---
pub struct SolidityFuzzer {
    /// target functions
    functions: Vec<FunctionSpec>,
}

pub fn function_selector(signature: &str) -> [u8; 4] {
    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(signature.as_bytes());
    keccak.finalize(&mut hash);
    [hash[0], hash[1], hash[2], hash[3]]
}

impl SolidityFuzzer {
    pub fn new(abi: Vec<ParsedFunction>) -> Self {
        Self {
            functions: abi
                .into_iter()
                .map(|parsed_function| {
                    let param_type = parsed_function
                        .inputs
                        .into_iter()
                        .map(|p| p.internal_type)
                        .collect_vec();
                    let signature =
                        parsed_function.name.clone() + "(" + param_type.join(",").as_str() + ")";
                    FunctionSpec {
                        selector: function_selector(&signature),
                        params: param_type
                            .into_iter()
                            .map(|pt| ParamKind::from_string(pt.as_str()))
                            .collect_vec(),
                        name: parsed_function.name,
                    }
                })
                .collect(),
        }
    }

    pub fn generate_random_calldata(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut calldata = vec![];
        let function = &self.functions[rng.gen_range(0..self.functions.len())];
        calldata.extend_from_slice(&function.selector);
        function.params.iter().for_each(|p| {
            calldata.extend_from_slice(&p.random());
        });
        println!("Call function {} with input {:?}", function.name, calldata);
        calldata
    }
}
