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

    fn check_alpenglow_clock_bounds(
        &self,
        bank: Arc<Bank>,
        parent_bank: Arc<Bank>,
    ) -> result::Result<(), BlockComponentVerifierError> {
        let (current_slot, parent_slot) = (bank.slot(), bank.parent_slot());
        let (current_time, parent_time) = (
            bank.clock().unix_timestamp,
            parent_bank.clock().unix_timestamp,
        );

        let diff_slots = current_slot.checked_sub(parent_slot).unwrap();

        let max_diff_time = DELTA_BLOCK
            .checked_mul(CLOCK_TIMEOUT_MULTIPLIER)
            .unwrap()
            .checked_mul(diff_slots as u32)
            .unwrap();
        let latest_acceptable_current_time = parent_time + (max_diff_time.as_nanos() as i64);

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

        let result = self.check_alpenglow_clock_bounds(bank.clone(), parent_bank);
        println!("SLOT {} CLOCK :: {:?}", bank.slot(), result);

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
        bank.set_clock(parent_epoch, footer.block_producer_time_nanos as i64);

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
