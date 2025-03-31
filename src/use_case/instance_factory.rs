use std::collections::HashMap;

use crate::{Factory, GenerationError, InstanceFactory};

use super::{factory::{ConcreteFactory, Type, TypeData}, InstanceId, PrivateInstanceKey, PublicInstanceKey};

#[allow(dead_code)]
struct ConcreteInstanceFactory<ConcreteFactory: Factory> {
    factory: ConcreteFactory,
    instanciation_lookup: HashMap<InstanceId, (PrivateInstanceKey, PublicInstanceKey)>
}

impl InstanceFactory for ConcreteInstanceFactory<ConcreteFactory<TypeData>> {
    type TargetFactory = ConcreteFactory<TypeData>;

    fn instanciate_template_from_ref(
        &self,
        target_id: InstanceId,
    ) -> Result<Type, GenerationError> {
        let (key, target_key) = self.instanciation_lookup.get(target_id).ok_or(GenerationError::InstanceFactoryNotRegistered)?;
        
        self.factory.generate_from_ref(key, target_key)
    }

    fn instanciate_template_from_mut(
            &mut self, 
            target_id: InstanceId,
        ) -> Result<<Self::TargetFactory as Factory>::Type, GenerationError> {
        let (key, target_key) = self.instanciation_lookup.get(target_id).ok_or(GenerationError::InstanceFactoryNotRegistered)?;
        
        self.factory.generate_from_mut(key, target_key)
            .or_else(|_| self.factory.generate_from_ref(key, target_key))
    }

    fn register(
        &mut self, 
        factory: &Self::TargetFactory, 
        target_private_instance_key: <Self::TargetFactory as Factory>::PrivateInstanceKey, 
        target_public_instance_key: <Self::TargetFactory as Factory>::PublicInstanceKey
    ) {
        if let Some(id) = factory.confirm(&target_private_instance_key, &target_public_instance_key) {
            self.instanciation_lookup.insert(id, (target_private_instance_key, target_public_instance_key));
        }
    }
}