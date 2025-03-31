use std::collections::HashMap;

use crate::{Factory, GenerationError, InstanceFactory};

use super::{factory::{ConcreteFactory, Type, TypeData}, InstanceId, InstanceKey, SecretInstanceKey};

#[allow(dead_code)]
struct ConcreteTemplate {
    target_id: InstanceId,
}

#[allow(dead_code)]
struct ConcreteInstanceFactory<ConcreteFactory: Factory> {
    factory: ConcreteFactory,
    instanciation_lookup: HashMap<InstanceId, (SecretInstanceKey, InstanceKey)>
}

impl InstanceFactory for ConcreteInstanceFactory<ConcreteFactory<TypeData>> {
    type Template = ConcreteTemplate;
    type TargetFactory = ConcreteFactory<TypeData>;

    fn instanciate_template_from_ref(&self, template: Self::Template) -> Result<Type, GenerationError> {
        let (key, target_key) = self.instanciation_lookup.get(template.target_id).ok_or(GenerationError::InstanceFactoryNotRegistered)?;
        
        self.factory.generate_from_ref(key, target_key)
    }

    fn instanciate_template_from_mut(
            &mut self, 
            template: Self::Template
        ) -> Result<<Self::TargetFactory as Factory>::Type, GenerationError> {
        let (key, target_key) = self.instanciation_lookup.get(template.target_id).ok_or(GenerationError::InstanceFactoryNotRegistered)?;
        
        self.factory.generate_from_mut(key, target_key)
            .or_else(|_| self.factory.generate_from_ref(key, target_key))
    }

    fn register(&mut self, factory: &Self::TargetFactory, target_secret_key: SecretInstanceKey, target_instance_key: InstanceKey) {
        if let Some(id) = factory.confirm(&target_secret_key, &target_instance_key) {
            self.instanciation_lookup.insert(id, (target_secret_key, target_instance_key));
        }
    }
}