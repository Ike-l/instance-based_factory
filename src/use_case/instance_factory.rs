use std::collections::HashMap;

use crate::{Factory, InstanceFactory, InstanciationError};

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

    fn instanciate_template(&self, template: Self::Template) -> Result<Type, InstanciationError> {
        let (key, target_key) = self.instanciation_lookup.get(template.target_id).ok_or(InstanciationError::RegistrationError)?;
        
        self.factory.generate(key, target_key).ok_or(InstanciationError::GenerationError)
    }

    fn register(&mut self, factory: &Self::TargetFactory, target_secret_key: SecretInstanceKey, target_instance_key: InstanceKey) {
        if let Some(id) = factory.confirm(&target_secret_key, &target_instance_key) {
            self.instanciation_lookup.insert(id, (target_secret_key, target_instance_key));
        }
    }
}