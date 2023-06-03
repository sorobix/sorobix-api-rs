use crossbeam_channel::{Receiver, Sender};

use crate::{services::channel_service::ChannelService, InCh};

pub struct WebSocketState {
    pub reciever_rec: Receiver<InCh>,
}
