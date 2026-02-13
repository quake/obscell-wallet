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

    /// Test that after rollback, the state can correctly continue scanning
    /// from the fork point. This is the expected behavior for reorg handling.
    #[test]
    fn test_scan_state_rollback_preserves_continuity() {
        let mut state = ScanState::new();

        // Simulate scanning blocks 100-105
        state.add_block(100, [1u8; 32]);
        state.add_block(101, [2u8; 32]);
        state.add_block(102, [3u8; 32]);
        state.add_block(103, [4u8; 32]);
        state.add_block(104, [5u8; 32]);
        state.add_block(105, [6u8; 32]);

        assert_eq!(state.last_scanned_block, Some(105));
        assert_eq!(state.next_block_to_scan(0), 106);

        // Simulate reorg detected at block 104 - fork at block 102
        // The new chain has block 103' with parent = block 102's hash
        let fork_parent = [3u8; 32]; // block 102's hash
        let fork_point = state.find_fork_point(&fork_parent);
        assert_eq!(fork_point, Some(102));

        // Rollback to fork point
        state.rollback_to(102);

        // After rollback:
        // - last_scanned_block should be 102
        // - next_block_to_scan should be 103 (to scan new chain)
        // - expected_parent_hash should be block 102's hash
        assert_eq!(state.last_scanned_block, Some(102));
        assert_eq!(state.next_block_to_scan(0), 103);
        assert_eq!(state.expected_parent_hash(), Some([3u8; 32]));

        // Should have blocks 100, 101, 102 in recent_blocks
        assert_eq!(state.recent_blocks.len(), 3);
    }

    /// Test that clear() completely resets the state.
    #[test]
    fn test_scan_state_clear_resets_everything() {
        let mut state = ScanState::new();

        state.add_block(100, [1u8; 32]);
        state.add_block(101, [2u8; 32]);
        state.add_block(102, [3u8; 32]);

        state.clear();

        assert_eq!(state.last_scanned_block, None);
        assert!(state.recent_blocks.is_empty());
        assert_eq!(state.expected_parent_hash(), None);
        // After clear, should start from provided start_block
        assert_eq!(state.next_block_to_scan(50), 50);
    }

    /// Test that rollback followed by clear is different from just rollback.
    /// This documents the bug: calling clear() after rollback loses the fork point info.
    #[test]
    fn test_scan_state_rollback_vs_clear() {
        let mut state1 = ScanState::new();
        let mut state2 = ScanState::new();

        // Both states scan the same blocks
        for (s, h) in [(100, [1u8; 32]), (101, [2u8; 32]), (102, [3u8; 32])] {
            state1.add_block(s, h);
            state2.add_block(s, h);
        }

        // State 1: proper rollback only
        state1.rollback_to(100);

        // State 2: rollback then clear (the bug)
        state2.rollback_to(100);
        state2.clear();

        // State 1 can continue from block 101
        assert_eq!(state1.next_block_to_scan(0), 101);
        assert_eq!(state1.expected_parent_hash(), Some([1u8; 32]));

        // State 2 lost everything and will restart from start_block
        assert_eq!(state2.next_block_to_scan(50), 50); // Uses start_block!
        assert_eq!(state2.expected_parent_hash(), None);
    }
}
