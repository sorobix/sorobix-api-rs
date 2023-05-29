use std::sync::{mpsc, Arc, Mutex};

use crate::models::compile_contract::ChannelData;

pub struct ChannelService {
    pub channel_data: ChannelData,
}

impl ChannelService {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel();

        ChannelService {
            channel_data: ChannelData { sender, receiver },
        }
    }

    pub fn get_channel_data(&self) -> &ChannelData {
        &self.channel_data
    }
}
