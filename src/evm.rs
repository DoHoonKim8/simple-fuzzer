use revm::{
    primitives::{Address, CreateScheme, ExecutionResult, Output, TransactTo, TxEnv},
    InMemoryDB, EVM,
};

pub struct Evm {
    evm: EVM<InMemoryDB>,
}

impl Default for Evm {
    fn default() -> Self {
        Self {
            evm: EVM {
                env: Default::default(),
                db: Some(Default::default()),
            },
        }
    }
}

impl Evm {
    /// Return code_size of given address.
    ///
    /// # Panics
    /// Panics if given address doesn't have bytecode.
    pub fn code_size(&mut self, address: Address) -> usize {
        self.evm.db.as_ref().unwrap().accounts[&address]
            .info
            .code
            .as_ref()
            .unwrap()
            .len()
    }

    /// Apply create transaction with given `bytecode` as creation bytecode.
    /// Return created `address`.
    ///
    /// # Panics
    /// Panics if execution reverts or halts unexpectedly.
    pub fn create(&mut self, bytecode: Vec<u8>) -> Address {
        let (_, output) = self.transact_success_or_panic(TxEnv {
            gas_limit: u64::MAX,
            transact_to: TransactTo::Create(CreateScheme::Create),
            data: bytecode.into(),
            ..Default::default()
        });
        match output {
            Output::Create(_, Some(address)) => address,
            _ => unreachable!(),
        }
    }

    /// Apply call transaction to given `address` with `calldata`.
    /// Returns `gas_used` and `return_data`.
    ///
    /// # Panics
    /// Panics if execution reverts or halts unexpectedly.
    pub fn call(&mut self, address: Address, calldata: Vec<u8>) -> (u64, Vec<u8>) {
        let (gas_used, output) = self.transact_success_or_panic(TxEnv {
            gas_limit: u64::MAX,
            transact_to: TransactTo::Call(address),
            data: calldata.into(),
            ..Default::default()
        });
        match output {
            Output::Call(output) => (gas_used, output.into()),
            _ => unreachable!(),
        }
    }

    fn transact_success_or_panic(&mut self, tx: TxEnv) -> (u64, Output) {
        self.evm.env.tx = tx;
        let result = self.evm.transact_commit().unwrap();
        self.evm.env.tx = Default::default();
        match result {
            ExecutionResult::Success {
                gas_used,
                output,
                logs,
                ..
            } => {
                if !logs.is_empty() {
                    println!("--- logs from {} ---", logs[0].address);
                    for (log_idx, log) in logs.iter().enumerate() {
                        println!("log#{log_idx}");
                        for (topic_idx, topic) in log.topics.iter().enumerate() {
                            println!("  topic{topic_idx}: {topic:?}");
                        }
                    }
                    println!("--- end ---");
                }
                (gas_used, output)
            }
            ExecutionResult::Revert { gas_used, output } => {
                panic!("Transaction reverts with gas_used {gas_used} and output {output:#x}")
            }
            ExecutionResult::Halt { reason, gas_used } => panic!(
                "Transaction halts unexpectedly with gas_used {gas_used} and reason {reason:?}"
            ),
        }
    }
}
