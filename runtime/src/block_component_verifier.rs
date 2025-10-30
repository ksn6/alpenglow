use {
    crate::bank::Bank,
    solana_entry::block_component::{
        BlockMarkerV1, VersionedBlockFooter, VersionedBlockHeader, VersionedBlockMarker,
    },
    std::{result, sync::Arc, time::Duration},
    thiserror::Error,
};

/// Time the leader has for producing and sending the block.
pub(crate) const DELTA_BLOCK: Duration = Duration::from_millis(400);

/// Clock multiplier for timeout bounds
const CLOCK_TIMEOUT_MULTIPLIER: u32 = 2;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlockComponentVerifierError {
    #[error("Missing block footer")]
    MissingBlockFooter,
    #[error("Missing block header")]
    MissingBlockHeader,
    #[error("Alpenglow clock bounds exceeded")]
    AlpenglowClockBoundsExceeded,
    #[error("Multiple block footers detected")]
    MultipleBlockFooters,
    #[error("Multiple block headers detected")]
    MultipleBlockHeaders,
}

pub struct BlockComponentVerifier {
    has_header: bool,
    has_footer: bool,
}

impl BlockComponentVerifier {
    pub fn new() -> Self {
        Self {
            has_header: false,
            has_footer: false,
        }
    }

    pub fn latest_acceptable_time(time: u64, diff_slots: u64) -> u64 {
        let max_diff_time = DELTA_BLOCK
            .checked_mul(CLOCK_TIMEOUT_MULTIPLIER)
            .unwrap()
            .checked_mul(diff_slots as u32)
            .unwrap();

        time + max_diff_time.as_nanos() as u64
    }

    pub fn skewed_time(current_time: u64, parent_time: u64, diff_slots: u64) -> u64 {
        if current_time <= parent_time {
            current_time.saturating_add(1)
        } else {
            let latest_acceptable_time =
                BlockComponentVerifier::latest_acceptable_time(current_time, diff_slots);
            latest_acceptable_time.min(current_time)
        }
    }

    fn check_alpenglow_clock_bounds(
        &self,
        bank: Arc<Bank>,
        parent_bank: Arc<Bank>,
    ) -> result::Result<(), BlockComponentVerifierError> {
        let (current_slot, parent_slot) = (bank.slot(), bank.parent_slot());

        // Get Alpenglow timestamps in nanoseconds
        let current_time = bank
            .alpenglow_timestamp_nanos
            .read()
            .unwrap()
            .expect("Current bank should have alpenglow_timestamp set by footer");

        // If parent doesn't have alpenglow_timestamp (e.g., genesis bank), skip clock bounds check
        let Some(parent_time) = *parent_bank.alpenglow_timestamp_nanos.read().unwrap() else {
            println!(
                "SLOT {} CLOCK skipping bounds check (parent has no alpenglow timestamp)",
                current_slot
            );
            return Ok(());
        };

        let diff_slots = current_slot.checked_sub(parent_slot).unwrap();
        let latest_acceptable_current_time =
            BlockComponentVerifier::latest_acceptable_time(parent_time, diff_slots);

        println!("SLOT {} CLOCK parent_time :: {}", current_slot, parent_time);
        println!(
            "SLOT {} CLOCK current_time :: {}",
            current_slot, current_time
        );
        println!(
            "SLOT {} CLOCK latest_acceptable_current_time :: {}",
            current_slot, latest_acceptable_current_time
        );

        if parent_time < current_time && current_time <= latest_acceptable_current_time {
            Ok(())
        } else {
            Err(BlockComponentVerifierError::AlpenglowClockBoundsExceeded)
        }
    }

    pub fn finish(
        &self,
        bank: Arc<Bank>,
        parent_bank: Arc<Bank>,
    ) -> result::Result<(), BlockComponentVerifierError> {
        if !self.has_footer {
            return Err(BlockComponentVerifierError::MissingBlockFooter);
        }

        if !self.has_header {
            return Err(BlockComponentVerifierError::MissingBlockHeader);
        }

        println!("SLOT {} HAS FOOTER :: {}", bank.slot(), self.has_footer);
        println!("SLOT {} HAS HEADER :: {}", bank.slot(), self.has_header);

        self.check_alpenglow_clock_bounds(bank.clone(), parent_bank)?;
        println!("SLOT {} CLOCK VERIFICATION PASSED", bank.slot());

        Ok(())
    }

    pub fn on_marker(
        &mut self,
        bank: Arc<Bank>,
        parent_bank: Arc<Bank>,
        marker: &VersionedBlockMarker,
    ) -> result::Result<(), BlockComponentVerifierError> {
        let marker = match marker {
            VersionedBlockMarker::V1(marker) | VersionedBlockMarker::Current(marker) => marker,
        };

        match marker {
            BlockMarkerV1::BlockFooter(footer) => self.on_footer(bank, parent_bank, footer),
            BlockMarkerV1::BlockHeader(header) => self.on_header(header),
            // We process UpdateParent messages on shred ingest, so no callback needed here
            BlockMarkerV1::UpdateParent(_) => Ok(()),
        }
    }

    fn on_footer(
        &mut self,
        bank: Arc<Bank>,
        parent_bank: Arc<Bank>,
        footer: &VersionedBlockFooter,
    ) -> result::Result<(), BlockComponentVerifierError> {
        if self.has_footer {
            return Err(BlockComponentVerifierError::MultipleBlockFooters);
        }

        let footer = match footer {
            VersionedBlockFooter::V1(footer) | VersionedBlockFooter::Current(footer) => footer,
        };

        // Update the bank's clock timestamp with the value from the block footer
        let parent_epoch = Some(parent_bank.epoch());
        bank.set_clock(parent_epoch, footer.block_producer_time_nanos);

        println!(
            "SLOT {} set timestamp {} {}",
            bank.slot(),
            bank.clock().unix_timestamp,
            footer.block_producer_time_nanos
        );

        self.has_footer = true;
        Ok(())
    }

    fn on_header(
        &mut self,
        _header: &VersionedBlockHeader,
    ) -> result::Result<(), BlockComponentVerifierError> {
        if self.has_header {
            return Err(BlockComponentVerifierError::MultipleBlockHeaders);
        }

        self.has_header = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bank::Bank, genesis_utils::create_genesis_config};
    use solana_entry::block_component::{BlockFooterV1, BlockHeaderV1};
    use solana_program::{hash::Hash, pubkey::Pubkey};
    use std::sync::Arc;
    use test_case::test_case;

    fn create_test_bank() -> Arc<Bank> {
        let genesis_config_info = create_genesis_config(10_000);
        Arc::new(Bank::new_for_tests(&genesis_config_info.genesis_config))
    }

    fn create_child_bank(parent: &Arc<Bank>, slot: u64) -> Arc<Bank> {
        Arc::new(Bank::new_from_parent(
            parent.clone(),
            &Pubkey::new_unique(),
            slot,
        ))
    }

    #[test_case(1u64 ; "1 slot difference")]
    #[test_case(2u64 ; "2 slot difference")]
    #[test_case(4u64 ; "4 slot difference")]
    #[test_case(8u64 ; "8 slot difference")]
    #[test_case(16u64 ; "16 slot difference")]
    fn test_latest_acceptable_time(diff_slots: u64) {
        let parent_time = 1_000_000_000; // 1 second in nanos
        let expected = parent_time
            + (DELTA_BLOCK.as_nanos() as u64 * CLOCK_TIMEOUT_MULTIPLIER as u64 * diff_slots);
        assert_eq!(
            BlockComponentVerifier::latest_acceptable_time(parent_time, diff_slots),
            expected
        );
    }

    #[test]
    fn test_skewed_time_backward() {
        // When current_time <= parent_time, should return current_time + 1
        let current_time = 1_000_000_000;
        let parent_time = 1_500_000_000;
        let diff_slots = 1;
        assert_eq!(
            BlockComponentVerifier::skewed_time(current_time, parent_time, diff_slots),
            current_time + 1
        );
    }

    #[test]
    fn test_skewed_time_forward() {
        // When current_time > parent_time, should return min(latest_acceptable, current_time)
        let parent_time = 1_000_000_000;
        let current_time = 1_500_000_000;
        let diff_slots = 1;
        let result = BlockComponentVerifier::skewed_time(current_time, parent_time, diff_slots);

        // Since current_time is likely within acceptable bounds, should return current_time
        assert_eq!(result, current_time);
    }

    #[test]
    fn test_missing_header_error() {
        let verifier = BlockComponentVerifier::new();
        let parent = create_test_bank();
        let bank = create_child_bank(&parent, 1);

        // Set footer but not header
        *bank.alpenglow_timestamp_nanos.write().unwrap() = Some(1_000_000_000);

        let mut v = verifier;
        v.has_footer = true;

        let result = v.finish(bank, parent);
        assert_eq!(result, Err(BlockComponentVerifierError::MissingBlockHeader));
    }

    #[test]
    fn test_missing_footer_error() {
        let verifier = BlockComponentVerifier::new();
        let parent = create_test_bank();
        let bank = create_child_bank(&parent, 1);

        let mut v = verifier;
        v.has_header = true;

        let result = v.finish(bank, parent);
        assert_eq!(result, Err(BlockComponentVerifierError::MissingBlockFooter));
    }

    #[test]
    fn test_multiple_headers_error() {
        let mut verifier = BlockComponentVerifier::new();
        let header = VersionedBlockHeader::V1(BlockHeaderV1 {
            parent_slot: 0,
            parent_block_id: Hash::default(),
        });

        // First header should succeed
        assert!(verifier.on_header(&header).is_ok());

        // Second header should fail
        let result = verifier.on_header(&header);
        assert_eq!(
            result,
            Err(BlockComponentVerifierError::MultipleBlockHeaders)
        );
    }

    #[test]
    fn test_multiple_footers_error() {
        let mut verifier = BlockComponentVerifier::new();
        let parent = create_test_bank();
        let bank = create_child_bank(&parent, 1);

        let footer = VersionedBlockFooter::V1(BlockFooterV1 {
            block_producer_time_nanos: 1_000_000_000,
            block_user_agent: vec![],
        });

        // First footer should succeed
        assert!(verifier
            .on_footer(bank.clone(), parent.clone(), &footer)
            .is_ok());

        // Second footer should fail
        let result = verifier.on_footer(bank, parent, &footer);
        assert_eq!(
            result,
            Err(BlockComponentVerifierError::MultipleBlockFooters)
        );
    }

    #[test]
    fn test_on_footer_sets_timestamp() {
        let mut verifier = BlockComponentVerifier::new();
        let parent = create_test_bank();
        let bank = create_child_bank(&parent, 1);

        let footer_time = 1_234_567_890_000_000_000; // nanos
        let footer = VersionedBlockFooter::V1(BlockFooterV1 {
            block_producer_time_nanos: footer_time,
            block_user_agent: vec![],
        });

        verifier.on_footer(bank.clone(), parent, &footer).unwrap();

        assert!(verifier.has_footer);

        // Verify alpenglow_timestamp_nanos is set correctly
        assert_eq!(
            *bank.alpenglow_timestamp_nanos.read().unwrap(),
            Some(footer_time)
        );

        // Verify clock sysvar is set correctly (should be in seconds, not nanoseconds)
        let clock = bank.clock();
        assert_eq!(clock.unix_timestamp, (footer_time / 1_000_000_000) as i64);
    }

    #[test]
    fn test_on_header_sets_flag() {
        let mut verifier = BlockComponentVerifier::new();
        let header = VersionedBlockHeader::V1(BlockHeaderV1 {
            parent_slot: 0,
            parent_block_id: Hash::default(),
        });

        verifier.on_header(&header).unwrap();
        assert!(verifier.has_header);
    }

    #[test]
    fn test_clock_bounds_parent_missing_timestamp() {
        let mut verifier = BlockComponentVerifier::new();
        verifier.has_header = true;
        verifier.has_footer = true;

        let parent = create_test_bank();
        let bank = create_child_bank(&parent, 1);

        // Set current bank timestamp but not parent (simulates genesis case)
        *bank.alpenglow_timestamp_nanos.write().unwrap() = Some(1_000_000_000);

        // Should succeed and skip bounds check
        let result = verifier.finish(bank, parent);
        assert!(result.is_ok());
    }

    #[test_case(1u64, 100_000_000u64 ; "1 slot 100ms later")]
    #[test_case(2u64, 500_000_000u64 ; "2 slots 500ms later")]
    #[test_case(4u64, 1_000_000_000u64 ; "4 slots 1s later")]
    #[test_case(8u64, 2_000_000_000u64 ; "8 slots 2s later")]
    fn test_clock_bounds_valid_time_progression(slot_diff: u64, time_offset: u64) {
        let parent_time = 1_000_000_000_000_000_000u64; // nanos
        let mut verifier = BlockComponentVerifier::new();
        verifier.has_header = true;
        verifier.has_footer = true;

        let parent = create_test_bank();
        let bank = create_child_bank(&parent, slot_diff);

        let current_time = parent_time + time_offset;

        *parent.alpenglow_timestamp_nanos.write().unwrap() = Some(parent_time);
        *bank.alpenglow_timestamp_nanos.write().unwrap() = Some(current_time);

        // Should succeed - time is progressing normally within bounds
        let result = verifier.finish(bank, parent);
        assert!(result.is_ok());
    }

    #[test]
    fn test_clock_bounds_time_not_progressing() {
        let mut verifier = BlockComponentVerifier::new();
        verifier.has_header = true;
        verifier.has_footer = true;

        let parent = create_test_bank();
        let bank = create_child_bank(&parent, 1);

        let parent_time = 1_000_000_000_000_000_000u64;
        let current_time = parent_time; // Same time, not progressing

        *parent.alpenglow_timestamp_nanos.write().unwrap() = Some(parent_time);
        *bank.alpenglow_timestamp_nanos.write().unwrap() = Some(current_time);

        // Should fail - time must progress
        let result = verifier.finish(bank, parent);
        assert_eq!(
            result,
            Err(BlockComponentVerifierError::AlpenglowClockBoundsExceeded)
        );
    }

    #[test_case(1u64, 10_000_000_000u64 ; "1 slot 10s ahead")]
    #[test_case(2u64, 20_000_000_000u64 ; "2 slots 20s ahead")]
    #[test_case(4u64, 40_000_000_000u64 ; "4 slots 40s ahead")]
    #[test_case(8u64, 80_000_000_000u64 ; "8 slots 80s ahead")]
    fn test_clock_bounds_time_too_far_ahead(slot_diff: u64, time_offset: u64) {
        let parent_time = 1_000_000_000_000_000_000u64;
        let mut verifier = BlockComponentVerifier::new();
        verifier.has_header = true;
        verifier.has_footer = true;

        let parent = create_test_bank();
        let bank = create_child_bank(&parent, slot_diff);

        let current_time = parent_time + time_offset;

        *parent.alpenglow_timestamp_nanos.write().unwrap() = Some(parent_time);
        *bank.alpenglow_timestamp_nanos.write().unwrap() = Some(current_time);

        // Should fail - time is too far ahead
        let result = verifier.finish(bank, parent);
        assert_eq!(
            result,
            Err(BlockComponentVerifierError::AlpenglowClockBoundsExceeded)
        );
    }

    #[test_case(1u64 ; "1 slot at exact boundary")]
    #[test_case(2u64 ; "2 slots at exact boundary")]
    #[test_case(4u64 ; "4 slots at exact boundary")]
    #[test_case(8u64 ; "8 slots at exact boundary")]
    #[test_case(16u64 ; "16 slots at exact boundary")]
    fn test_clock_bounds_at_exact_boundary(diff_slots: u64) {
        let parent_time = 1_000_000_000_000_000_000u64;
        let mut verifier = BlockComponentVerifier::new();
        verifier.has_header = true;
        verifier.has_footer = true;

        let parent = create_test_bank();
        let bank = create_child_bank(&parent, diff_slots);

        let current_time = BlockComponentVerifier::latest_acceptable_time(parent_time, diff_slots);

        *parent.alpenglow_timestamp_nanos.write().unwrap() = Some(parent_time);
        *bank.alpenglow_timestamp_nanos.write().unwrap() = Some(current_time);

        // Should succeed - exactly at the boundary
        let result = verifier.finish(bank, parent);
        assert!(result.is_ok());
    }

    #[test_case(1u64 ; "1 slot just beyond boundary")]
    #[test_case(2u64 ; "2 slots just beyond boundary")]
    #[test_case(4u64 ; "4 slots just beyond boundary")]
    #[test_case(8u64 ; "8 slots just beyond boundary")]
    #[test_case(16u64 ; "16 slots just beyond boundary")]
    fn test_clock_bounds_just_beyond_boundary(diff_slots: u64) {
        let parent_time = 1_000_000_000_000_000_000u64;
        let mut verifier = BlockComponentVerifier::new();
        verifier.has_header = true;
        verifier.has_footer = true;

        let parent = create_test_bank();
        let bank = create_child_bank(&parent, diff_slots);

        let current_time =
            BlockComponentVerifier::latest_acceptable_time(parent_time, diff_slots) + 1;

        *parent.alpenglow_timestamp_nanos.write().unwrap() = Some(parent_time);
        *bank.alpenglow_timestamp_nanos.write().unwrap() = Some(current_time);

        // Should fail - just beyond the boundary
        let result = verifier.finish(bank, parent);
        assert_eq!(
            result,
            Err(BlockComponentVerifierError::AlpenglowClockBoundsExceeded)
        );
    }

    #[test]
    fn test_on_marker_processes_header() {
        let mut verifier = BlockComponentVerifier::new();
        let marker = VersionedBlockMarker::V1(BlockMarkerV1::BlockHeader(
            VersionedBlockHeader::V1(BlockHeaderV1 {
                parent_slot: 0,
                parent_block_id: Hash::default(),
            }),
        ));

        let parent = create_test_bank();
        let bank = create_child_bank(&parent, 1);

        verifier.on_marker(bank, parent, &marker).unwrap();
        assert!(verifier.has_header);
    }

    #[test]
    fn test_on_marker_processes_footer() {
        let mut verifier = BlockComponentVerifier::new();
        let footer_time = 1_234_567_890_000_000_000;
        let marker = VersionedBlockMarker::V1(BlockMarkerV1::BlockFooter(
            VersionedBlockFooter::V1(BlockFooterV1 {
                block_producer_time_nanos: footer_time,
                block_user_agent: vec![],
            }),
        ));

        let parent = create_test_bank();
        let bank = create_child_bank(&parent, 1);

        verifier.on_marker(bank.clone(), parent, &marker).unwrap();
        assert!(verifier.has_footer);

        // Verify alpenglow_timestamp_nanos is set correctly
        assert_eq!(
            *bank.alpenglow_timestamp_nanos.read().unwrap(),
            Some(footer_time)
        );

        // Verify clock sysvar is set correctly (should be in seconds, not nanoseconds)
        let clock = bank.clock();
        assert_eq!(clock.unix_timestamp, (footer_time / 1_000_000_000) as i64);
    }

    #[test]
    fn test_complete_workflow_success() {
        let mut verifier = BlockComponentVerifier::new();
        let parent = create_test_bank();
        let bank = create_child_bank(&parent, 1);

        let parent_time = 1_000_000_000_000_000_000u64;
        *parent.alpenglow_timestamp_nanos.write().unwrap() = Some(parent_time);

        // Process header
        let header = VersionedBlockHeader::V1(BlockHeaderV1 {
            parent_slot: 0,
            parent_block_id: Hash::default(),
        });
        verifier.on_header(&header).unwrap();

        // Process footer with valid timestamp
        let footer = VersionedBlockFooter::V1(BlockFooterV1 {
            block_producer_time_nanos: parent_time + 100_000_000, // 100ms later
            block_user_agent: vec![],
        });
        verifier
            .on_footer(bank.clone(), parent.clone(), &footer)
            .unwrap();

        // Verify alpenglow_timestamp_nanos is set correctly
        let expected_timestamp = parent_time + 100_000_000;
        assert_eq!(
            *bank.alpenglow_timestamp_nanos.read().unwrap(),
            Some(expected_timestamp)
        );

        // Verify clock sysvar is set correctly (should be in seconds, not nanoseconds)
        let clock = bank.clock();
        assert_eq!(
            clock.unix_timestamp,
            (expected_timestamp / 1_000_000_000) as i64
        );

        // Finish verification
        let result = verifier.finish(bank, parent);
        assert!(result.is_ok());
    }
}
