mod factory;
mod instance_factory;

#[derive(Hash, Clone, Copy)]
pub struct PrivateInstanceKey(u64);
impl From<u64> for PrivateInstanceKey {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct PublicInstanceKey(u64);
impl From<u64> for PublicInstanceKey {
    fn from(value: u64) -> Self {
        Self(value)
    }
}


type InstanceId = &'static str;