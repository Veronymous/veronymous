use crate::error::TokenServiceException;
use crate::error::TokenServiceException::{
    DBError, DeserializationError, IllegalStateError, NotFoundError, SerializationError,
};
use crate::VeronymousTokenServiceConfig;
use ps_signatures::keys::{PsParams, PsPublicKey, PsSigningKey};
use ps_signatures::serde::Serializable;
use rand::thread_rng;
use rocksdb::{Options, DB};
use std::time::{SystemTime, UNIX_EPOCH};

const SUFFIX_PARAMS: &str = "-key_params";
const SUFFIX_SIGNING_KEY: &str = "-signing_key";
const SUFFIX_PUBLIC_KEY: &str = "-public_key";

/*
* TODO: Clean this up
*/
#[derive(Debug)]
pub struct KeyManagementService {
    db: DB,

    key_lifetime: u64,

    current_key_id: Option<String>,

    key_params: Option<PsParams>,

    signing_key: Option<PsSigningKey>,

    public_key: Option<PsPublicKey>,

    next_key_id: Option<String>,

    next_key_params: Option<PsParams>,

    next_public_key: Option<PsPublicKey>,

    next_signing_key: Option<PsSigningKey>,
}

impl KeyManagementService {
    pub fn create(config: &VeronymousTokenServiceConfig) -> Self {
        let mut options = Options::default();
        options.create_if_missing(true);

        let db = DB::open(&options, &config.key_file).unwrap();

        let mut service = Self {
            db,
            // Convert minutes to seconds
            key_lifetime: config.key_lifetime * 60,
            current_key_id: None,
            signing_key: None,
            key_params: None,
            public_key: None,
            next_key_id: None,
            next_key_params: None,
            next_public_key: None,
            next_signing_key: None,
        };

        service.load_keys().unwrap();

        service
    }

    pub fn get_current_public_key(&self) -> (PsParams, PsPublicKey) {
        (
            self.key_params.as_ref().unwrap().clone(),
            self.public_key.as_ref().unwrap().clone(),
        )
    }

    pub fn get_current_signing_key(&self) -> PsSigningKey {
        self.signing_key.as_ref().unwrap().clone()
    }

    pub fn get_next_public_key(&self) -> (PsParams, PsPublicKey) {
        (
            self.next_key_params.as_ref().unwrap().clone(),
            self.next_public_key.as_ref().unwrap().clone(),
        )
    }

    pub fn get_next_signing_key(&self) -> PsSigningKey {
        self.next_signing_key.as_ref().unwrap().clone()
    }
}

impl KeyManagementService {
    pub fn load_keys(&mut self) -> Result<(), TokenServiceException> {
        let (base_key_id, next_base_key_id) = self.calculate_base_key_ids();

        debug!("Current base key id: {}", base_key_id);
        debug!("Next base key id: {}", next_base_key_id);

        self.load_current_keys(base_key_id)?;
        self.load_next_keys(next_base_key_id)?;

        Ok(())
    }

    fn load_current_keys(&mut self, base_key_id: String) -> Result<(), TokenServiceException> {
        // Check if key is already loaded
        match &self.current_key_id {
            None => {
                self.current_key_id = Some(base_key_id);
            }
            Some(key_id) => {
                if key_id == &base_key_id {
                    // Already loaded, exit function
                    return Ok(());
                } else {
                    // Set the new key id
                    self.current_key_id = Some(base_key_id);
                }
            }
        };

        if !self.current_key_exists()? {
            self.provision_current_keys()?;
        } else {
            // Load keys
            self.key_params = Some(self.get_key_params(&self.get_current_key_params_id()?)?);
            self.signing_key = Some(self.get_signing_key(&self.get_current_signing_key_id()?)?);
            self.public_key = Some(self.get_public_key(&self.get_current_public_key_id()?)?);
        }

        Ok(())
    }

    // TODO: Might not properly load next keys
    fn load_next_keys(&mut self, base_key_id: String) -> Result<(), TokenServiceException> {
        // Check if key is already loaded
        match &self.next_key_id {
            None => {
                self.next_key_id = Some(base_key_id);
            }
            Some(key_id) => {
                if key_id == &base_key_id {
                    // Already loaded, exit function
                    return Ok(());
                } else {
                    // Set the new key id
                    self.next_key_id = Some(base_key_id.clone());
                }
            }
        };

        if !self.next_key_exists()? {
            self.provision_next_keys()?;
        } else {
            // Load keys
            self.next_key_params = Some(self.get_key_params(&self.get_next_key_params_id()?)?);
            self.next_public_key = Some(self.get_public_key(&self.get_next_public_key_id()?)?);
            self.next_signing_key = Some(self.get_signing_key(&self.get_next_signing_key_id()?)?);
        }

        Ok(())
    }

    fn provision_current_keys(&mut self) -> Result<(), TokenServiceException> {
        let mut rng = thread_rng();

        // Generate the params and keys
        let params = PsParams::generate(&mut rng);
        let signing_key = PsSigningKey::generate(1, &params, &mut rng);
        let public_key = signing_key.derive_public_key(&params);

        // Store them
        self.store_key_params(&params, &self.get_current_key_params_id()?)?;
        self.store_signing_key(&signing_key, &self.get_current_signing_key_id()?)?;
        self.store_public_key(&public_key, &self.get_current_public_key_id()?)?;

        self.key_params = Some(params);
        self.signing_key = Some(signing_key);
        self.public_key = Some(public_key);

        Ok(())
    }

    fn provision_next_keys(&mut self) -> Result<(), TokenServiceException> {
        let mut rng = thread_rng();

        // Generate the params and keys
        let params = PsParams::generate(&mut rng);
        let signing_key = PsSigningKey::generate(1, &params, &mut rng);
        let public_key = signing_key.derive_public_key(&params);

        // Store them
        self.store_key_params(&params, &self.get_next_key_params_id()?)?;
        self.store_signing_key(&signing_key, &self.get_next_signing_key_id()?)?;
        self.store_public_key(&public_key, &self.get_next_public_key_id()?)?;

        self.next_key_params = Some(params);
        self.next_public_key = Some(public_key);
        self.next_signing_key = Some(signing_key);

        Ok(())
    }

    fn current_key_exists(&self) -> Result<bool, TokenServiceException> {
        let exists = self.db.key_may_exist(self.get_current_key_params_id()?)
            && self.db.key_may_exist(self.get_current_signing_key_id()?)
            && self.db.key_may_exist(self.get_current_public_key_id()?);

        Ok(exists)
    }

    fn next_key_exists(&self) -> Result<bool, TokenServiceException> {
        let exists = self.db.key_may_exist(self.get_next_key_params_id()?)
            && self.db.key_may_exist(self.get_next_signing_key_id()?)
            && self.db.key_may_exist(self.get_next_public_key_id()?);

        Ok(exists)
    }

    fn get_key_params(&self, key_id: &String) -> Result<PsParams, TokenServiceException> {
        let result = self
            .db
            .get(key_id)
            .map_err(|e| DBError(format!("Could not get key params. {:?}", e)))?;

        let params = match result {
            Some(params) => params,
            None => return Err(NotFoundError(format!("Key params not found."))),
        };

        let params = PsParams::deserialize(&params).map_err(|e| {
            DeserializationError(format!("Could not deserialize key params. {:?}", e))
        })?;

        Ok(params)
    }

    fn get_public_key(&self, key_id: &String) -> Result<PsPublicKey, TokenServiceException> {
        let result = self
            .db
            .get(key_id)
            .map_err(|e| DBError(format!("Could not get public key. {:?}", e)))?;

        let public_key = match result {
            Some(key) => key,
            None => return Err(NotFoundError(format!("Public key not found."))),
        };

        let public_key = PsPublicKey::deserialize(&public_key).map_err(|e| {
            DeserializationError(format!("Could not deserialize public key. {:?}", e))
        })?;

        Ok(public_key)
    }

    fn get_signing_key(&self, key_id: &String) -> Result<PsSigningKey, TokenServiceException> {
        let result = self
            .db
            .get(key_id)
            .map_err(|e| DBError(format!("Could not get signing key. {:?}", e)))?;

        let signing_key = match result {
            Some(key) => key,
            None => return Err(NotFoundError(format!("Signing key not found."))),
        };

        let signing_key = PsSigningKey::deserialize(&signing_key).map_err(|e| {
            DeserializationError(format!("Could not deserialize signing key. {:?}", e))
        })?;

        Ok(signing_key)
    }

    fn store_key_params(
        &mut self,
        params: &PsParams,
        params_id: &String,
    ) -> Result<(), TokenServiceException> {
        let params_serialized = params
            .serialize()
            .map_err(|e| SerializationError(format!("Could not serialize params. {:?}", e)))?;

        self.db
            .put(params_id, &params_serialized)
            .map_err(|e| DBError(format!("Could not store params. {:?}", e)))?;

        Ok(())
    }

    fn store_signing_key(
        &mut self,
        signing_key: &PsSigningKey,
        key_id: &String,
    ) -> Result<(), TokenServiceException> {
        //let key_id = self.get_current_signing_key_id()?;
        let key_serialized = signing_key
            .serialize()
            .map_err(|e| SerializationError(format!("Could not serialize signing key. {:?}", e)))?;

        self.db
            .put(key_id, &key_serialized)
            .map_err(|e| DBError(format!("Could not store signing key. {:?}", e)))?;

        Ok(())
    }

    fn store_public_key(
        &mut self,
        public_key: &PsPublicKey,
        key_id: &String,
    ) -> Result<(), TokenServiceException> {
        let key_serialized = public_key
            .serialize()
            .map_err(|e| SerializationError(format!("Could not serialize public key. {:?}", e)))?;

        self.db
            .put(key_id, &key_serialized)
            .map_err(|e| DBError(format!("Could not store public keys. {:?}", e)))?;

        Ok(())
    }

    fn get_current_key_params_id(&self) -> Result<String, TokenServiceException> {
        let base_key_id = self.get_current_base_key_id()?;
        Ok(format!("{}{}", base_key_id, SUFFIX_PARAMS))
    }

    fn get_current_signing_key_id(&self) -> Result<String, TokenServiceException> {
        let base_key_id = self.get_current_base_key_id()?;
        Ok(format!("{}{}", base_key_id, SUFFIX_SIGNING_KEY))
    }

    fn get_current_public_key_id(&self) -> Result<String, TokenServiceException> {
        let base_key_id = self.get_current_base_key_id()?;
        Ok(format!("{}{}", base_key_id, SUFFIX_PUBLIC_KEY))
    }

    fn get_current_base_key_id(&self) -> Result<String, TokenServiceException> {
        match &self.current_key_id {
            Some(key_id) => Ok(key_id.clone()),
            None => Err(IllegalStateError(format!("'current_key_id is not set.'"))),
        }
    }

    fn get_next_key_params_id(&self) -> Result<String, TokenServiceException> {
        let base_key_id = self.get_next_base_key_id()?;
        Ok(format!("{}{}", base_key_id, SUFFIX_PARAMS))
    }

    fn get_next_signing_key_id(&self) -> Result<String, TokenServiceException> {
        let base_key_id = self.get_next_base_key_id()?;
        Ok(format!("{}{}", base_key_id, SUFFIX_SIGNING_KEY))
    }

    fn get_next_public_key_id(&self) -> Result<String, TokenServiceException> {
        let base_key_id = self.get_next_base_key_id()?;
        Ok(format!("{}{}", base_key_id, SUFFIX_PUBLIC_KEY))
    }

    fn get_next_base_key_id(&self) -> Result<String, TokenServiceException> {
        match &self.next_key_id {
            Some(key_id) => Ok(key_id.clone()),
            None => Err(IllegalStateError(format!("'current_key_id is not set.'"))),
        }
    }

    // returns (current key id, next key id)
    fn calculate_base_key_ids(&self) -> (String, String) {
        let now = SystemTime::now();
        let now = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let current_epoch = now - (now % self.key_lifetime);

        let next_epoch = current_epoch + self.key_lifetime;

        (current_epoch.to_string(), next_epoch.to_string())
    }
}
