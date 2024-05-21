use wasm_bindgen::{prelude::*, JsValue};

pub mod crypto;
pub mod errors;

#[wasm_bindgen]
pub fn decrypt(data: JsValue, password: &str) -> Result<Vec<u8>, JsValue> {
    let array = js_sys::Uint8Array::new(&data);
    let bytes: Vec<u8> = array.to_vec();

    let decrypted_bytes = match crate::crypto::decrypt_from_bytes(bytes, password) {
        Ok(bytes) => bytes,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };

    Ok(decrypted_bytes)
}

#[cfg(test)]
mod test {
    #[test]
    fn test_docx() {
        let docx = include_bytes!("test.docx").to_vec();
        let expected = include_bytes!("test_decrypted.docx").to_vec();

        let bytes = crate::crypto::decrypt_from_bytes(docx, "test").unwrap();

        assert_eq!(bytes, expected);
    }
}
