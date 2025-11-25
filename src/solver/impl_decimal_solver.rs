macro_rules! impl_decimal_solver {
    ([$single_block_solver:ty, $double_block_solver:ty] => $decimal_solver:ident) => {
        /// Safe decimal nonce solver variant
        pub enum $decimal_solver {
            /// Single block solver variant
            SingleBlock($single_block_solver),
            /// Double block solver variant
            DoubleBlock($double_block_solver),
        }

        impl From<SingleBlockMessage> for $decimal_solver {
            fn from(message: SingleBlockMessage) -> Self {
                Self::SingleBlock(SingleBlockSolver::from(message))
            }
        }

        impl From<DoubleBlockMessage> for $decimal_solver {
            fn from(message: DoubleBlockMessage) -> Self {
                Self::DoubleBlock(DoubleBlockSolver::from(message))
            }
        }

        impl From<DecimalMessage> for $decimal_solver {
            fn from(message: DecimalMessage) -> Self {
                match message {
                    DecimalMessage::SingleBlock(message) => {
                        Self::SingleBlock(<$single_block_solver>::from(message))
                    }
                    DecimalMessage::DoubleBlock(message) => {
                        Self::DoubleBlock(<$double_block_solver>::from(message))
                    }
                }
            }
        }

        impl crate::solver::Solver for $decimal_solver {
            fn set_limit(&mut self, limit: u64) {
                match self {
                    Self::SingleBlock(solver) => solver.set_limit(limit),
                    Self::DoubleBlock(solver) => solver.set_limit(limit),
                }
            }

            fn get_attempted_nonces(&self) -> u64 {
                match self {
                    Self::SingleBlock(solver) => solver.get_attempted_nonces(),
                    Self::DoubleBlock(solver) => solver.get_attempted_nonces(),
                }
            }

            fn solve<const TYPE: u8>(&mut self, target: u64, mask: u64) -> Option<(u64, [u32; 8])> {
                match self {
                    Self::SingleBlock(solver) => solver.solve::<TYPE>(target, mask),
                    Self::DoubleBlock(solver) => solver.solve::<TYPE>(target, mask),
                }
            }
        }
    };
}
