use std::{collections::HashMap, hash::{DefaultHasher, Hash, Hasher}};

use rand::{rngs::ThreadRng, Rng};

use crate::{Factory, GenerationError};

use super::{InstanceId, InstanceKey, SecretInstanceKey};

#[allow(dead_code)]
#[derive(Clone)]
enum Kind {
    Signal,
    Interrupt,
}

#[allow(dead_code)]
pub struct Type {
    display_name: InstanceId,
    key: InstanceKey,
    data: TypeData
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct TypeData (Kind, bool);

#[allow(dead_code)]
pub struct ConcreteFactory<Data> {
    rng: ThreadRng, 
    generation_map: HashMap<InstanceKey, Option<Data>>,
    id_map: HashMap<InstanceId, InstanceKey>
}

impl ConcreteFactory<TypeData> {
    fn get_id(&self, key: &InstanceKey) -> Option<&InstanceId> {
        return self.id_map
            .iter()
            .find_map(|(instance_id, instance_key)| {
                (instance_key == key).then(|| instance_id)
            });
    }

    #[allow(dead_code)]
    pub fn register(&mut self, instance_id: InstanceId) -> Option<SecretInstanceKey> {
        if self.id_map.contains_key(instance_id) {
            return None
        }

        let key = self.rng.random::<u64>();
        let secret_key = Self::gen_id(&key);

        self.generation_map.insert(key, None);
        self.id_map.insert(instance_id, key);

        Some(secret_key)
    }

    #[allow(dead_code)]
    pub fn write_data(&mut self, secret_key: &SecretInstanceKey, instance_key: &InstanceKey, data: TypeData) {
        if Self::confirm_key(secret_key, instance_key) {
            self.generation_map.insert(*instance_key, Some(data));
        }
    }
}

impl Factory for ConcreteFactory<TypeData> {
    type InstanceId = InstanceId;
    type PrivateInstanceKey = SecretInstanceKey;
    type PublicInstanceKey = InstanceKey;

    type Type = Type;

    fn confirm(&self, secret_key: &SecretInstanceKey, key: &InstanceKey) -> Option<&InstanceId> {
        if Self::confirm_key(secret_key, key) {
            return self.get_id(key)
        }
        None
    }
    
    fn generate_from_ref(
        &self, 
        secret_key: &SecretInstanceKey, 
        instance_key: &InstanceKey
    ) -> Result<Self::Type, GenerationError> {
        let data = self.generation_map
            .get(instance_key)
            .ok_or(GenerationError::FactoryNotRegistered)?;

        let id = self.get_id(instance_key).ok_or(GenerationError::FactoryNotRegistered)?;

        if Self::confirm_key(secret_key, instance_key) {
            return Ok(
                Type { 
                    display_name: id, 
                    key: *instance_key, 
                    data: data.clone().ok_or(GenerationError::NoneData)?
                }
            );
        }

        Err(GenerationError::KeyMisMatch)
    }

    fn generate_from_mut(
            &mut self, 
            secret_key: &Self::PrivateInstanceKey, 
            instance_key: &Self::PublicInstanceKey
        ) -> Result<Self::Type, GenerationError> {
        let data = self.generation_map
            .get_mut(instance_key)
            .ok_or(GenerationError::FactoryNotRegistered)?
            .take()
            .ok_or(GenerationError::NoneData)?;

        let id = self.id_map
            .iter()
            .find_map(
                |(id, key)| 
                    if key == instance_key {
                        Some(id) 
                    } else { 
                        None 
                    }
            ).ok_or(GenerationError::FactoryNotRegistered)?;

        if Self::confirm_key(secret_key, instance_key) {
            return Ok(
                Type { 
                    display_name: id, 
                    key: *instance_key, 
                    data
                }
            );
        }

        Err(GenerationError::KeyMisMatch)
    }

    fn gen_id(
        secret_key: &Self::PrivateInstanceKey
    ) -> Self::PublicInstanceKey{
        let mut hasher = DefaultHasher::new();
        secret_key.hash(&mut hasher);
        hasher.finish().into()
    }
}
