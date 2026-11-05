//! JavaScript bindings. Structured data crosses the boundary as JSON strings:
//! simple, debuggable, and fast enough for per-navigation queries.

use wasm_bindgen::prelude::*;

use crate::engine;

#[wasm_bindgen]
pub struct Engine(engine::Engine);

fn js_err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen]
impl Engine {
    /// Verify + decode a signed bundle. `installed_version` guards rollbacks (0 = none).
    pub fn load(bytes: &[u8], pubkey_hex: &str, installed_version: f64) -> Result<Engine, JsError> {
        engine::Engine::load(bytes, pubkey_hex, installed_version as u64)
            .map(Engine)
            .map_err(js_err)
    }

    pub fn version(&self) -> f64 {
        self.0.meta().version as f64
    }

    pub fn tenant(&self) -> String {
        self.0.meta().tenant_id.clone()
    }

    /// `{"action":"Allow"|"Block","reason":{...}}` or `null` for non-http(s) URLs.
    pub fn check_url(&self, url: &str) -> String {
        serde_json::to_string(&self.0.check_url(url)).unwrap_or_else(|_| "null".into())
    }

    /// `{"selectors":[...],"scriptlets":[{"name":..,"args":[..]}]}`
    pub fn cosmetics_for(&self, host: &str) -> String {
        let c = self.0.cosmetics_for(host);
        serde_json::json!({ "selectors": c.selectors, "scriptlets": c.scriptlets }).to_string()
    }

    /// `{"rules":[{"priority":n,"action":"allow|block","domains":[..]}],"truncated":n}`
    pub fn dnr_plan(&self, max_domains: u32) -> String {
        serde_json::to_string(&self.0.dnr_plan(max_domains as usize)).unwrap_or_default()
    }

    /// Source metadata (license + attribution) as JSON array.
    pub fn sources(&self) -> String {
        serde_json::to_string(&self.0.meta().sources).unwrap_or_else(|_| "[]".into())
    }
}
