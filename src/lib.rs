pub enum GenerationError {
    InstanceFactoryNotRegistered,
    FactoryNotRegistered,
    NoneData,
    KeyMisMatch,
    NoClone,
}
// i need to restrict 

pub trait Factory {
    type PrivateInstanceKey;
    type PublicInstanceKey: PartialEq + From<u64>;
    type InstanceId;

    type Type;

    fn generate_from_ref(
        &self, 
        private_instance_key: &Self::PrivateInstanceKey, 
        public_instance_key: &Self::PublicInstanceKey
    ) -> Result<Self::Type, GenerationError>;

    fn generate_from_mut(
        &mut self, 
        private_instance_key: &Self::PrivateInstanceKey, 
        public_instance_key: &Self::PublicInstanceKey
    ) -> Result<Self::Type, GenerationError>;

    fn confirm(
        &self, 
        private_instance_key: &Self::PrivateInstanceKey, 
        public_instance_key: &Self::PublicInstanceKey
    ) -> Option<&Self::InstanceId>;

    fn confirm_key(
        private_instance_key: &Self::PrivateInstanceKey, 
        public_instance_key: &Self::PublicInstanceKey
    ) -> bool {
        Self::gen_id(private_instance_key) == *public_instance_key
    }

    fn gen_id(
        private_key: &Self::PrivateInstanceKey
    ) -> Self::PublicInstanceKey;

}

pub trait InstanceFactory {
    type TargetFactory: Factory;

    fn register(
        &mut self, 
        factory: &Self::TargetFactory, 
        target_private_instance_key: <Self::TargetFactory as Factory>::PrivateInstanceKey, 
        target_public_instance_key: <Self::TargetFactory as Factory>::PublicInstanceKey
    );

    fn instanciate_template_from_ref(
        &self, 
        target_id: <Self::TargetFactory as Factory>::InstanceId,
    ) -> Result<<Self::TargetFactory as Factory>::Type, GenerationError>;

    fn instanciate_template_from_mut(
        &mut self, 
        target_id: <Self::TargetFactory as Factory>::InstanceId,
    ) -> Result<<Self::TargetFactory as Factory>::Type, GenerationError>;
}

// Notes
// There should not be a public method on Type to bypass this *without* a way to confirm it happened
// There should not be any way to get any SecretKey (if stored in either factory (like debug))
// This design pattern hinges on the fact private fields are only accessible in or under the decleration module

// Is there a way with this method to allow specific others? (restrict who knows the private key beyond either no one else or everyone else). This would be like an actual trade

mod use_case;