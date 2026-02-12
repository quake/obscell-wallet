//! Scan state tracking for block-based scanning.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Maximum number of recent blocks to track for reorg detection.
pub const MAX_RECENT_BLOCKS: usize = 64;

/// Scan state persisted in LMDB.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanState {
    /// Last successfully scanned block number.
    pub last_scanned_block: Option<u64>,
    /// Recent block hashes for reorg detection: (block_number, block_hash).
    /// Most recent is at the back.
    pub recent_blocks: VecDeque<(u64, [u8; 32])>,
}

impl ScanState {
    /// Create a new empty scan state.
    pub fn new() -> Self {
        Self {
            last_scanned_block: None,
            recent_blocks: VecDeque::new(),
        }
    }

    /// Add a new block to the recent blocks list.
    pub fn add_block(&mut self, block_number: u64, block_hash: [u8; 32]) {
        self.recent_blocks.push_back((block_number, block_hash));
        while self.recent_blocks.len() > MAX_RECENT_BLOCKS {
            self.recent_blocks.pop_front();
        }
        self.last_scanned_block = Some(block_number);
    }

    /// Get the expected parent hash for the next block.
    /// Returns None if no blocks have been scanned yet.
    pub fn expected_parent_hash(&self) -> Option<[u8; 32]> {
        self.recent_blocks.back().map(|(_, hash)| *hash)
    }

    /// Find the fork point when a reorg is detected.
    /// Returns the block number to roll back to (the last valid block).
    /// Returns None if no common ancestor is found in recent_blocks.
    pub fn find_fork_point(&self, parent_hash: &[u8; 32]) -> Option<u64> {
        // Search backwards through recent_blocks for matching hash
        for (block_number, hash) in self.recent_blocks.iter().rev() {
            if hash == parent_hash {
                return Some(*block_number);
            }
        }
        None
    }

    /// Roll back to a specific block number.
    /// Removes all blocks after the given block number.
    pub fn rollback_to(&mut self, block_number: u64) {
        while let Some(&(num, _)) = self.recent_blocks.back() {
            if num <= block_number {
                break;
            }
            self.recent_blocks.pop_back();
        }
        self.last_scanned_block = self.recent_blocks.back().map(|(num, _)| *num);
    }

    /// Get the next block number to scan.
    pub fn next_block_to_scan(&self, start_block: u64) -> u64 {
        match self.last_scanned_block {
            Some(last) => last + 1,
            None => start_block,
        }
    }

    /// Clear all state (for full rescan).
    pub fn clear(&mut self) {
        self.last_scanned_block = None;
        self.recent_blocks.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_state_add_block() {
        let mut state = ScanState::new();

        state.add_block(100, [1u8; 32]);
        assert_eq!(state.last_scanned_block, Some(100));
        assert_eq!(state.recent_blocks.len(), 1);

        state.add_block(101, [2u8; 32]);
        assert_eq!(state.last_scanned_block, Some(101));
        assert_eq!(state.recent_blocks.len(), 2);
    }

    #[test]
    fn test_scan_state_max_recent_blocks() {
        let mut state = ScanState::new();

        // Add more than MAX_RECENT_BLOCKS
        for i in 0..(MAX_RECENT_BLOCKS + 10) {
            state.add_block(i as u64, [i as u8; 32]);
        }

        assert_eq!(state.recent_blocks.len(), MAX_RECENT_BLOCKS);
        // First block should be trimmed
        assert_eq!(state.recent_blocks.front().unwrap().0, 10);
    }

    #[test]
    fn test_scan_state_expected_parent_hash() {
        let mut state = ScanState::new();
        assert_eq!(state.expected_parent_hash(), None);

        state.add_block(100, [0xab; 32]);
        assert_eq!(state.expected_parent_hash(), Some([0xab; 32]));
    }

    #[test]
    fn test_scan_state_find_fork_point() {
        let mut state = ScanState::new();
        state.add_block(100, [1u8; 32]);
        state.add_block(101, [2u8; 32]);
        state.add_block(102, [3u8; 32]);

        // Fork after block 101
        assert_eq!(state.find_fork_point(&[2u8; 32]), Some(101));

        // Unknown parent
        assert_eq!(state.find_fork_point(&[99u8; 32]), None);
    }

    #[test]
    fn test_scan_state_rollback() {
        let mut state = ScanState::new();
        state.add_block(100, [1u8; 32]);
        state.add_block(101, [2u8; 32]);
        state.add_block(102, [3u8; 32]);

        state.rollback_to(100);

        assert_eq!(state.last_scanned_block, Some(100));
        assert_eq!(state.recent_blocks.len(), 1);
        assert_eq!(state.recent_blocks.back().unwrap().0, 100);
    }

    #[test]
    fn test_scan_state_next_block() {
        let mut state = ScanState::new();
        assert_eq!(state.next_block_to_scan(50), 50); // Use start_block

        state.add_block(100, [1u8; 32]);
        assert_eq!(state.next_block_to_scan(50), 101); // Continue from last
    }
}
