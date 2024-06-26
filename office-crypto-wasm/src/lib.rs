use wasm_bindgen::{prelude::*, JsValue};

#[wasm_bindgen]
pub fn decrypt(data: JsValue, password: &str) -> Result<Vec<u8>, JsValue> {
    let array = js_sys::Uint8Array::new(&data);
    let bytes: Vec<u8> = array.to_vec();

    let decrypted_bytes = match office_crypto_rs::decrypt_from_bytes(bytes, password) {
        Ok(bytes) => bytes,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };

    Ok(decrypted_bytes)
}
