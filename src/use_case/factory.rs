use std::{collections::HashMap, hash::{DefaultHasher, Hash, Hasher}};

use rand::{rngs::ThreadRng, Rng};

use crate::{Factory, GenerationError};

use super::{InstanceId, PrivateInstanceKey, PublicInstanceKey};

#[allow(dead_code)]
#[derive(Clone)]
enum Kind {
    Signal,
    Interrupt,
}

#[allow(dead_code)]
pub struct Type {
    display_name: InstanceId,
    key: PublicInstanceKey,
    data: TypeData
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct TypeData (Kind, bool);

#[allow(dead_code)]
pub struct ConcreteFactory<Data> {
    rng: ThreadRng, 
    generation_map: HashMap<PublicInstanceKey, Option<Data>>,
    id_map: HashMap<InstanceId, PublicInstanceKey>
}

impl ConcreteFactory<TypeData> {
    fn get_id(
        &self, 
        public_instance_key: &PublicInstanceKey
    ) -> Option<&InstanceId> {
        return self.id_map
            .iter()
            .find_map(|(instance_id, instance_key)| {
                (instance_key == public_instance_key).then(|| instance_id)
            });
    }

    #[allow(dead_code)]
    pub fn register(
        &mut self, 
        instance_id: InstanceId
    ) -> Option<PrivateInstanceKey> {
        if self.id_map.contains_key(instance_id) {
            return None
        }

        let private_key = self.rng.random::<u64>().into();
        let public_key = Self::gen_id(&private_key);

        self.generation_map.insert(public_key, None);
        self.id_map.insert(instance_id, public_key);

        Some(private_key)
    }

    #[allow(dead_code)]
    pub fn write_data(
        &mut self, 
        secret_key: &PrivateInstanceKey, 
        instance_key: &PublicInstanceKey, 
        data: TypeData
    ) {
        if Self::confirm_key(secret_key, instance_key) {
            self.generation_map.insert(*instance_key, Some(data));
        }
    }
}

impl Factory for ConcreteFactory<TypeData> {
    type InstanceId = InstanceId;
    type PrivateInstanceKey = PrivateInstanceKey;
    type PublicInstanceKey = PublicInstanceKey;

    type Type = Type;

    fn confirm(
        &self, 
        private_instance_key: &Self::PrivateInstanceKey, 
        public_instance_key: &Self::PublicInstanceKey
    ) -> Option<&InstanceId> {
        if Self::confirm_key(private_instance_key, public_instance_key) {
            return self.get_id(public_instance_key)
        }
        None
    }
    
    fn generate_from_ref(
        &self, 
        private_instance_key: &Self::PrivateInstanceKey, 
        public_instance_key: &Self::PublicInstanceKey
    ) -> Result<Self::Type, GenerationError> {
        let data = self.generation_map
            .get(public_instance_key)
            .ok_or(GenerationError::FactoryNotRegistered)?;

        let id = self.get_id(public_instance_key).ok_or(GenerationError::FactoryNotRegistered)?;

        if Self::confirm_key(private_instance_key, public_instance_key) {
            return Ok(
                Type { 
                    display_name: id, 
                    key: *public_instance_key, 
                    data: data.clone().ok_or(GenerationError::NoneData)?
                }
            );
        }

        Err(GenerationError::KeyMisMatch)
    }

    fn generate_from_mut(
        &mut self, 
        private_instance_key: &Self::PrivateInstanceKey, 
        public_instance_key: &Self::PublicInstanceKey
    ) -> Result<Self::Type, GenerationError> {
        let data = self.generation_map
            .get_mut(public_instance_key)
            .ok_or(GenerationError::FactoryNotRegistered)?
            .take()
            .ok_or(GenerationError::NoneData)?;

        let id = self.get_id(public_instance_key).ok_or(GenerationError::FactoryNotRegistered)?;

        if Self::confirm_key(private_instance_key, public_instance_key) {
            return Ok(
                Type { 
                    display_name: id, 
                    key: *public_instance_key, 
                    data
                }
            );
        }

        Err(GenerationError::KeyMisMatch)
    }

    fn gen_id(
        private_instance_key: &Self::PrivateInstanceKey
    ) -> Self::PublicInstanceKey{
        let mut hasher = DefaultHasher::new();
        private_instance_key.hash(&mut hasher);
        hasher.finish().into()
    }
}
