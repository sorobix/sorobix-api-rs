use crossbeam_channel::{Receiver, Sender};

use crate::{services::channel_service::ChannelService, InCh, InLaw};

pub struct WebSocketState {
    pub sender_kafka: Sender<InLaw>,
}
