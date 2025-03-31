use std::collections::HashMap;

use rand::{rngs::ThreadRng, Rng};

use crate::Factory;

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
    generation_map: HashMap<InstanceKey, Data>,
    id_map: HashMap<InstanceId, InstanceKey>
}

impl ConcreteFactory<TypeData> {
    pub fn register(&mut self, instance_id: InstanceId) -> Option<SecretInstanceKey> {
        if self.id_map.contains_key(instance_id) {
            return None
        }

        let key = self.rng.random::<u64>();
        let secret_key = Self::gen_id(&key);

        self.id_map.insert(instance_id, key);

        Some(secret_key)
    }

    pub fn write_data(&mut self, secret_key: &SecretInstanceKey, instance_key: &InstanceKey, data: TypeData) {
        if Self::confirm_key(secret_key, instance_key) {
            self.generation_map.insert(*instance_key, data);
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
            return self.id_map
                .iter()
                .find_map(
                    |(instance_id, instance_key)|
                        if instance_key == key {
                            Some(instance_id)
                        } else { 
                            None 
                        }
                )
        }  

        None
    }

    fn generate(&self, secret_key: &SecretInstanceKey, instance_key: &InstanceKey) -> Option<Self::Type> {
        let data = self.generation_map.get(instance_key)?;
        let id = self.id_map.iter().find_map(|(id, key)| if key == instance_key { Some(id) } else { None })?;

        if Self::confirm_key(secret_key, instance_key) {
            return Some(
                Type { 
                    display_name: id, 
                    key: *instance_key, 
                    data: data.clone()
                }
            );
        }

        None
    }
}
