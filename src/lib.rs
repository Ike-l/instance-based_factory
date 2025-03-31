pub enum GenerationError {
    InstanceFactoryNotRegistered,
    FactoryNotRegistered,
    NoneData,
    KeyMisMatch,
    NoClone,
}

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
    type Template;
    type TargetFactory: Factory;

    fn register(
        &mut self, 
        factory: &Self::TargetFactory, 
        target_private_instance_key: <Self::TargetFactory as Factory>::PrivateInstanceKey, 
        target_public_instance_key: <Self::TargetFactory as Factory>::PublicInstanceKey
    );

    fn instanciate_template_from_ref(
        &self, 
        template: Self::Template
    ) -> Result<<Self::TargetFactory as Factory>::Type, GenerationError>;

    fn instanciate_template_from_mut(
        &mut self, 
        template: Self::Template
    ) -> Result<<Self::TargetFactory as Factory>::Type, GenerationError>;
}

// Notes
// There should not be a public method on Type to bypass this *without* a way to confirm it happened
// There should not be any way to get any SecretKey (if stored in either factory (like debug))
// This design pattern hinges on the fact that types cannot be instantiated without 1. a public method and 2. being in or under the type in the module hierarchy

mod use_case;