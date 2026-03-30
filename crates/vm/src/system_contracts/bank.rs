//! Bank Module - Token Operations
//!
//! Handles all token transfers, escrows, burns, and balance tracking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::error::{SystemContractError, SystemContractResult};
use super::events::BankEvent;
use super::types::{Address, Hash, TokenAmount};
use super::{GenesisConfig, BURN_ADDRESS};

// =============================================================================
// BANK CONFIGURATION
// =============================================================================

/// Bank configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BankConfig {
    /// Token symbol
    pub symbol: String,
    /// Token name
    pub name: String,
    /// Decimals (typically 18)
    pub decimals: u8,
    /// Initial supply
    pub initial_supply: TokenAmount,
    /// Maximum supply (0 = unlimited)
    pub max_supply: TokenAmount,
}

impl Default for BankConfig {
    fn default() -> Self {
        Self {
            symbol: "AETHEL".into(),
            name: "Aethelred Token".into(),
            decimals: 18,
            initial_supply: 1_000_000_000_000_000_000_000_000_000, // 1 billion
            max_supply: 0,                                         // No cap (deflationary via burn)
        }
    }
}

// =============================================================================
// ACCOUNT STATE
// =============================================================================

/// Account balance and state
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct AccountState {
    /// Available balance
    pub balance: TokenAmount,
    /// Locked balance (in escrow, staking, etc.)
    pub locked: TokenAmount,
    /// Account nonce
    pub nonce: u64,
    /// Account locked until (0 = not locked)
    pub locked_until: u64,
}


impl AccountState {
    /// Get available (unlocked) balance
    pub fn available(&self) -> TokenAmount {
        self.balance.saturating_sub(self.locked)
    }

    /// Check if account is locked
    pub fn is_locked(&self, current_time: u64) -> bool {
        self.locked_until > current_time
    }
}

// =============================================================================
// ESCROW
// =============================================================================

/// Escrow state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Escrow {
    /// Escrow ID
    pub id: Hash,
    /// Source address
    pub from: Address,
    /// Intended recipient (can be zero for undetermined)
    pub to: Address,
    /// Escrowed amount
    pub amount: TokenAmount,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp (0 = no expiry)
    pub expires_at: u64,
    /// Release conditions (encoded)
    pub conditions: Vec<u8>,
    /// Whether escrow is released
    pub released: bool,
}

// =============================================================================
// BANK
// =============================================================================

/// Bank for token operations
pub struct Bank {
    /// Configuration
    config: BankConfig,

    /// Account balances
    accounts: HashMap<Address, AccountState>,

    /// Active escrows
    escrows: HashMap<Hash, Escrow>,

    /// Total supply (excludes burned)
    total_supply: TokenAmount,

    /// Total burned
    total_burned: TokenAmount,

    /// Event queue
    events: Vec<BankEvent>,

    /// Current block height (set externally)
    current_block: u64,
}

impl Bank {
    /// Create new bank with config
    pub fn new(config: BankConfig) -> Self {
        Self {
            total_supply: config.initial_supply,
            config,
            accounts: HashMap::new(),
            escrows: HashMap::new(),
            total_burned: 0,
            events: Vec::new(),
            current_block: 0,
        }
    }

    /// Create bank from genesis configuration
    pub fn from_genesis(genesis: &GenesisConfig) -> SystemContractResult<Self> {
        let mut bank = Self::new(BankConfig::default());

        // Apply initial allocations
        for alloc in &genesis.allocations {
            let account = bank.accounts.entry(alloc.address).or_default();
            account.balance = alloc.balance;
        }

        Ok(bank)
    }

    /// Set current block height
    pub fn set_block(&mut self, height: u64) {
        self.current_block = height;
    }

    /// Get and clear pending events
    pub fn drain_events(&mut self) -> Vec<BankEvent> {
        std::mem::take(&mut self.events)
    }

    // =========================================================================
    // BALANCE OPERATIONS
    // =========================================================================

    /// Get account balance
    pub fn balance_of(&self, address: &Address) -> TokenAmount {
        self.accounts.get(address).map(|a| a.balance).unwrap_or(0)
    }

    /// Get available (unlocked) balance
    pub fn available_balance(&self, address: &Address) -> TokenAmount {
        self.accounts
            .get(address)
            .map(|a| a.available())
            .unwrap_or(0)
    }

    /// Get locked balance
    pub fn get_locked_balance(&self, address: &Address) -> TokenAmount {
        self.accounts.get(address).map(|a| a.locked).unwrap_or(0)
    }

    /// Get account state
    pub fn get_account(&self, address: &Address) -> Option<&AccountState> {
        self.accounts.get(address)
    }

    /// Get total supply
    pub fn total_supply(&self) -> TokenAmount {
        self.total_supply
    }

    /// Get total burned
    pub fn total_burned(&self) -> TokenAmount {
        self.total_burned
    }

    // =========================================================================
    // TRANSFER OPERATIONS
    // =========================================================================

    /// Transfer tokens between accounts
    pub fn transfer(
        &mut self,
        from: Address,
        to: Address,
        amount: TokenAmount,
    ) -> SystemContractResult<()> {
        if amount == 0 {
            return Err(SystemContractError::InvalidAmount {
                reason: "Amount must be > 0".into(),
            });
        }

        // Check sender balance
        let sender = self.accounts.entry(from).or_default();
        if sender.available() < amount {
            return Err(SystemContractError::InsufficientBalance {
                required: amount,
                available: sender.available(),
            });
        }

        // Check if sender is locked
        if sender.is_locked(self.current_block) {
            return Err(SystemContractError::AccountLocked {
                address: hex::encode(from),
                unlock_time: sender.locked_until,
            });
        }

        // Debit sender
        sender.balance = sender.balance.saturating_sub(amount);

        // Credit receiver (or burn if burn address)
        if to == BURN_ADDRESS {
            self.total_supply = self.total_supply.saturating_sub(amount);
            self.total_burned = self.total_burned.saturating_add(amount);
        } else {
            let receiver = self.accounts.entry(to).or_default();
            receiver.balance = receiver.balance.saturating_add(amount);
        }

        // Emit event
        self.events.push(BankEvent::Transfer {
            from,
            to,
            amount,
            block_height: self.current_block,
        });

        Ok(())
    }

    /// Mint new tokens (only for genesis/rewards)
    pub fn mint(&mut self, to: Address, amount: TokenAmount) -> SystemContractResult<()> {
        if amount == 0 {
            return Ok(());
        }

        // Check max supply
        if self.config.max_supply > 0 {
            let new_supply = self.total_supply.saturating_add(amount);
            if new_supply > self.config.max_supply {
                return Err(SystemContractError::InvalidAmount {
                    reason: format!(
                        "Would exceed max supply: {} + {} > {}",
                        self.total_supply, amount, self.config.max_supply
                    ),
                });
            }
        }

        let account = self.accounts.entry(to).or_default();
        account.balance = account.balance.saturating_add(amount);
        self.total_supply = self.total_supply.saturating_add(amount);

        Ok(())
    }

    /// Burn tokens
    pub fn burn(&mut self, from: Address, amount: TokenAmount) -> SystemContractResult<()> {
        self.transfer(from, BURN_ADDRESS, amount)
    }

    // =========================================================================
    // LOCK OPERATIONS
    // =========================================================================

    /// Lock tokens in an account (for staking, escrow, etc.)
    pub fn lock(&mut self, address: &Address, amount: TokenAmount) -> SystemContractResult<()> {
        let account = self.accounts.get_mut(address).ok_or({
            SystemContractError::InsufficientBalance {
                required: amount,
                available: 0,
            }
        })?;

        if account.available() < amount {
            return Err(SystemContractError::InsufficientBalance {
                required: amount,
                available: account.available(),
            });
        }

        account.locked = account.locked.saturating_add(amount);
        Ok(())
    }

    /// Unlock tokens
    pub fn unlock(&mut self, address: &Address, amount: TokenAmount) -> SystemContractResult<()> {
        let account = self
            .accounts
            .get_mut(address)
            .ok_or_else(|| SystemContractError::staker_not_found(address))?;

        if account.locked < amount {
            return Err(SystemContractError::CannotUnstake {
                requested: amount,
                available: account.locked,
            });
        }

        account.locked = account.locked.saturating_sub(amount);
        Ok(())
    }

    /// Lock account (prevent all transfers)
    pub fn lock_account(
        &mut self,
        address: &Address,
        until: u64,
        reason: &str,
    ) -> SystemContractResult<()> {
        let account = self.accounts.entry(*address).or_default();
        account.locked_until = until;

        self.events.push(BankEvent::AccountLocked {
            account: *address,
            until,
            reason: reason.into(),
            block_height: self.current_block,
        });

        Ok(())
    }

    /// Unlock account
    pub fn unlock_account(&mut self, address: &Address) -> SystemContractResult<()> {
        let account = self
            .accounts
            .get_mut(address)
            .ok_or_else(|| SystemContractError::staker_not_found(address))?;

        account.locked_until = 0;

        self.events.push(BankEvent::AccountUnlocked {
            account: *address,
            block_height: self.current_block,
        });

        Ok(())
    }

    // =========================================================================
    // ESCROW OPERATIONS
    // =========================================================================

    /// Create an escrow
    pub fn create_escrow(
        &mut self,
        id: Hash,
        from: Address,
        to: Address,
        amount: TokenAmount,
        expires_at: u64,
        conditions: Vec<u8>,
    ) -> SystemContractResult<()> {
        if self.escrows.contains_key(&id) {
            return Err(SystemContractError::InvalidAmount {
                reason: "Escrow already exists".into(),
            });
        }

        // Lock the tokens
        self.lock(&from, amount)?;

        // Create escrow record
        let escrow = Escrow {
            id,
            from,
            to,
            amount,
            created_at: self.current_block,
            expires_at,
            conditions,
            released: false,
        };

        self.escrows.insert(id, escrow);

        self.events.push(BankEvent::EscrowCreated {
            escrow_id: id,
            from,
            amount,
            release_conditions: "custom".into(),
            block_height: self.current_block,
        });

        Ok(())
    }

    /// Release escrow to recipient
    pub fn release_escrow(&mut self, id: &Hash, to: Address) -> SystemContractResult<TokenAmount> {
        let (amount, from, released) = self
            .escrows
            .get(id)
            .map(|escrow| (escrow.amount, escrow.from, escrow.released))
            .ok_or_else(|| SystemContractError::EscrowNotFound {
                escrow_id: hex::encode(id),
            })?;

        if released {
            return Err(SystemContractError::EscrowNotFound {
                escrow_id: hex::encode(id),
            });
        }

        // Unlock from sender
        self.unlock(&from, amount)?;

        // Transfer to recipient
        let sender = self.accounts.get_mut(&from).unwrap();
        sender.balance = sender.balance.saturating_sub(amount);

        let receiver = self.accounts.entry(to).or_default();
        receiver.balance = receiver.balance.saturating_add(amount);

        if let Some(escrow) = self.escrows.get_mut(id) {
            escrow.released = true;
        }

        self.events.push(BankEvent::EscrowReleased {
            escrow_id: *id,
            to,
            amount,
            block_height: self.current_block,
        });

        Ok(amount)
    }

    /// Refund escrow to sender
    pub fn refund_escrow(&mut self, id: &Hash, reason: &str) -> SystemContractResult<TokenAmount> {
        let (amount, from, released) = self
            .escrows
            .get(id)
            .map(|escrow| (escrow.amount, escrow.from, escrow.released))
            .ok_or_else(|| SystemContractError::EscrowNotFound {
                escrow_id: hex::encode(id),
            })?;

        if released {
            return Err(SystemContractError::EscrowNotFound {
                escrow_id: hex::encode(id),
            });
        }

        // Unlock tokens (they're already in sender's account)
        self.unlock(&from, amount)?;

        if let Some(escrow) = self.escrows.get_mut(id) {
            escrow.released = true;
        }

        self.events.push(BankEvent::EscrowRefunded {
            escrow_id: *id,
            to: from,
            amount,
            reason: reason.into(),
            block_height: self.current_block,
        });

        Ok(amount)
    }

    /// Get escrow by ID
    pub fn get_escrow(&self, id: &Hash) -> Option<&Escrow> {
        self.escrows.get(id)
    }

    // =========================================================================
    // SLASH OPERATIONS
    // =========================================================================

    /// Slash locked tokens (for penalties)
    pub fn slash(
        &mut self,
        address: &Address,
        amount: TokenAmount,
    ) -> SystemContractResult<TokenAmount> {
        let account = self
            .accounts
            .get_mut(address)
            .ok_or_else(|| SystemContractError::staker_not_found(address))?;

        // Can only slash up to locked amount
        let slash_amount = amount.min(account.locked);
        if slash_amount == 0 {
            return Ok(0);
        }

        // Remove from locked and balance
        account.locked = account.locked.saturating_sub(slash_amount);
        account.balance = account.balance.saturating_sub(slash_amount);

        // Burn the slashed amount
        self.total_supply = self.total_supply.saturating_sub(slash_amount);
        self.total_burned = self.total_burned.saturating_add(slash_amount);

        Ok(slash_amount)
    }

    // =========================================================================
    // NONCE OPERATIONS
    // =========================================================================

    /// Get account nonce
    pub fn nonce_of(&self, address: &Address) -> u64 {
        self.accounts.get(address).map(|a| a.nonce).unwrap_or(0)
    }

    /// Increment account nonce
    pub fn increment_nonce(&mut self, address: &Address) {
        let account = self.accounts.entry(*address).or_default();
        account.nonce += 1;
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_bank() -> Bank {
        let mut bank = Bank::new(BankConfig::default());

        // Give test accounts some balance
        let account1 = bank.accounts.entry([1u8; 32]).or_default();
        account1.balance = 1_000_000;

        let account2 = bank.accounts.entry([2u8; 32]).or_default();
        account2.balance = 500_000;

        bank
    }

    #[test]
    fn test_transfer() {
        let mut bank = setup_bank();

        bank.transfer([1u8; 32], [3u8; 32], 100_000).unwrap();

        assert_eq!(bank.balance_of(&[1u8; 32]), 900_000);
        assert_eq!(bank.balance_of(&[3u8; 32]), 100_000);
    }

    #[test]
    fn test_transfer_insufficient_balance() {
        let mut bank = setup_bank();

        let result = bank.transfer([1u8; 32], [3u8; 32], 2_000_000);
        assert!(matches!(
            result,
            Err(SystemContractError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn test_burn() {
        let mut bank = setup_bank();
        let initial_supply = bank.total_supply();

        bank.burn([1u8; 32], 100_000).unwrap();

        assert_eq!(bank.balance_of(&[1u8; 32]), 900_000);
        assert_eq!(bank.total_supply(), initial_supply - 100_000);
        assert_eq!(bank.total_burned(), 100_000);
    }

    #[test]
    fn test_lock_unlock() {
        let mut bank = setup_bank();

        bank.lock(&[1u8; 32], 500_000).unwrap();
        assert_eq!(bank.available_balance(&[1u8; 32]), 500_000);

        bank.unlock(&[1u8; 32], 200_000).unwrap();
        assert_eq!(bank.available_balance(&[1u8; 32]), 700_000);
    }

    #[test]
    fn test_escrow() {
        let mut bank = setup_bank();
        let escrow_id = [100u8; 32];

        // Create escrow
        bank.create_escrow(escrow_id, [1u8; 32], [3u8; 32], 100_000, 1000, vec![])
            .unwrap();

        assert_eq!(bank.available_balance(&[1u8; 32]), 900_000);

        // Release escrow
        let released = bank.release_escrow(&escrow_id, [3u8; 32]).unwrap();
        assert_eq!(released, 100_000);
        assert_eq!(bank.balance_of(&[3u8; 32]), 100_000);
        assert_eq!(bank.balance_of(&[1u8; 32]), 900_000);
    }

    #[test]
    fn test_slash() {
        let mut bank = setup_bank();

        // Lock some tokens first
        bank.lock(&[1u8; 32], 500_000).unwrap();

        // Slash locked tokens
        let slashed = bank.slash(&[1u8; 32], 200_000).unwrap();
        assert_eq!(slashed, 200_000);
        assert_eq!(bank.balance_of(&[1u8; 32]), 800_000);

        // Verify burned
        assert!(bank.total_burned() >= 200_000);
    }

    #[test]
    fn test_account_lock() {
        let mut bank = setup_bank();
        bank.set_block(100);

        bank.lock_account(&[1u8; 32], 200, "test").unwrap();

        let account = bank.get_account(&[1u8; 32]).unwrap();
        assert!(account.is_locked(100));
        assert!(!account.is_locked(200));
    }
}
