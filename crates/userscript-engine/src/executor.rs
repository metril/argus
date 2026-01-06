//! JavaScript executor using Boa engine
//!
//! Provides script execution with GM_* API injection and sandboxing.

use crate::{gm_api::GmApi, Error, Result};
use boa_engine::{
    context::ContextBuilder, native_function::NativeFunction, object::ObjectInitializer,
    property::Attribute, Context, JsResult, JsValue, Source,
};
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, error, warn};

/// JavaScript executor for userscripts
pub struct ScriptExecutor {
    /// Boa JavaScript context
    context: Context,
    /// GM API instance
    gm_api: Arc<GmApi>,
}

impl ScriptExecutor {
    /// Create a new script executor
    pub fn new(gm_api: Arc<GmApi>) -> Result<Self> {
        let mut context = ContextBuilder::new().build().map_err(|e| {
            Error::ScriptExecution(format!("Failed to create JS context: {}", e))
        })?;

        // Initialize with GM_* API
        Self::inject_gm_api(&mut context, gm_api.clone())?;

        Ok(Self { context, gm_api })
    }

    /// Execute a userscript
    pub fn execute(&mut self, source: &str, script_name: &str) -> Result<()> {
        debug!("Executing userscript: {}", script_name);

        let result = self
            .context
            .eval(Source::from_bytes(source))
            .map_err(|e| Error::ScriptExecution(format!("Execution failed: {}", e)));

        match result {
            Ok(_) => {
                debug!("Userscript executed successfully: {}", script_name);
                Ok(())
            }
            Err(e) => {
                error!("Userscript execution error in {}: {}", script_name, e);
                Err(e)
            }
        }
    }

    /// Inject GM_* API into the JavaScript context
    fn inject_gm_api(context: &mut Context, gm_api: Arc<GmApi>) -> Result<()> {
        let global = context.global_object().clone();

        // Create GM object
        let mut gm_object = ObjectInitializer::new(context);

        // Storage APIs
        {
            let api = gm_api.clone();
            let set_value = NativeFunction::from_copy_closure_with_captures(
                move |_this, args, api, context| {
                    let name = args
                        .get(0)
                        .and_then(|v| v.as_string())
                        .ok_or_else(|| {
                            boa_engine::JsError::from_opaque(JsValue::new("name must be a string"))
                        })?
                        .to_std_string_escaped();

                    let value = args.get(1).cloned().unwrap_or(JsValue::undefined());
                    let json_value = js_value_to_json(value, context)?;

                    api.set_value(&name, json_value)
                        .map_err(|e| boa_engine::JsError::from_opaque(JsValue::new(e.to_string())))?;

                    Ok(JsValue::undefined())
                },
                api,
            );

            gm_object.function(set_value, "setValue", 2);
        }

        {
            let api = gm_api.clone();
            let get_value = NativeFunction::from_copy_closure_with_captures(
                move |_this, args, api, context| {
                    let name = args
                        .get(0)
                        .and_then(|v| v.as_string())
                        .ok_or_else(|| {
                            boa_engine::JsError::from_opaque(JsValue::new("name must be a string"))
                        })?
                        .to_std_string_escaped();

                    let default_value = args
                        .get(1)
                        .map(|v| js_value_to_json(v.clone(), context))
                        .transpose()?;

                    let result = api
                        .get_value(&name, default_value)
                        .map_err(|e| boa_engine::JsError::from_opaque(JsValue::new(e.to_string())))?;

                    json_to_js_value(result, context)
                },
                api,
            );

            gm_object.function(get_value, "getValue", 2);
        }

        {
            let api = gm_api.clone();
            let delete_value = NativeFunction::from_copy_closure_with_captures(
                move |_this, args, api, _context| {
                    let name = args
                        .get(0)
                        .and_then(|v| v.as_string())
                        .ok_or_else(|| {
                            boa_engine::JsError::from_opaque(JsValue::new("name must be a string"))
                        })?
                        .to_std_string_escaped();

                    api.delete_value(&name)
                        .map_err(|e| boa_engine::JsError::from_opaque(JsValue::new(e.to_string())))?;

                    Ok(JsValue::undefined())
                },
                api,
            );

            gm_object.function(delete_value, "deleteValue", 1);
        }

        {
            let api = gm_api.clone();
            let list_values = NativeFunction::from_copy_closure_with_captures(
                move |_this, _args, api, context| {
                    let values = api
                        .list_values()
                        .map_err(|e| boa_engine::JsError::from_opaque(JsValue::new(e.to_string())))?;

                    let arr = boa_engine::object::JsArray::new(context);
                    for (i, value) in values.iter().enumerate() {
                        arr.set(i, JsValue::new(value.clone()), context)?;
                    }

                    Ok(arr.into())
                },
                api,
            );

            gm_object.function(list_values, "listValues", 0);
        }

        // Info API
        {
            let api = gm_api.clone();
            let info = NativeFunction::from_copy_closure_with_captures(
                move |_this, _args, api, context| {
                    let info_value = api.info();
                    json_to_js_value(info_value, context)
                },
                api,
            );

            gm_object.function(info, "info", 0);
        }

        // Log API
        {
            let api = gm_api.clone();
            let log = NativeFunction::from_copy_closure_with_captures(
                move |_this, args, api, _context| {
                    let message = args
                        .get(0)
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "".to_string());

                    api.log(&message);
                    Ok(JsValue::undefined())
                },
                api,
            );

            gm_object.function(log, "log", 1);
        }

        // Advanced APIs (placeholders for Week 14)
        {
            let api = gm_api.clone();
            let add_style = NativeFunction::from_copy_closure_with_captures(
                move |_this, args, api, _context| {
                    let css = args
                        .get(0)
                        .and_then(|v| v.as_string())
                        .ok_or_else(|| {
                            boa_engine::JsError::from_opaque(JsValue::new("css must be a string"))
                        })?
                        .to_std_string_escaped();

                    api.add_style(&css)
                        .map_err(|e| boa_engine::JsError::from_opaque(JsValue::new(e.to_string())))?;

                    Ok(JsValue::undefined())
                },
                api,
            );

            gm_object.function(add_style, "addStyle", 1);
        }

        {
            let api = gm_api.clone();
            let open_in_tab = NativeFunction::from_copy_closure_with_captures(
                move |_this, args, api, context| {
                    let url = args
                        .get(0)
                        .and_then(|v| v.as_string())
                        .ok_or_else(|| {
                            boa_engine::JsError::from_opaque(JsValue::new("url must be a string"))
                        })?
                        .to_std_string_escaped();

                    let options = args
                        .get(1)
                        .map(|v| js_value_to_json(v.clone(), context))
                        .transpose()?;

                    api.open_in_tab(&url, options)
                        .map_err(|e| boa_engine::JsError::from_opaque(JsValue::new(e.to_string())))?;

                    Ok(JsValue::undefined())
                },
                api,
            );

            gm_object.function(open_in_tab, "openInTab", 2);
        }

        {
            let api = gm_api.clone();
            let notification = NativeFunction::from_copy_closure_with_captures(
                move |_this, args, api, context| {
                    let details = args
                        .get(0)
                        .map(|v| js_value_to_json(v.clone(), context))
                        .transpose()?
                        .unwrap_or(Value::Null);

                    api.notification(details)
                        .map_err(|e| boa_engine::JsError::from_opaque(JsValue::new(e.to_string())))?;

                    Ok(JsValue::undefined())
                },
                api,
            );

            gm_object.function(notification, "notification", 1);
        }

        {
            let api = gm_api.clone();
            let xml_http_request = NativeFunction::from_copy_closure_with_captures(
                move |_this, args, api, context| {
                    let details = args
                        .get(0)
                        .map(|v| js_value_to_json(v.clone(), context))
                        .transpose()?
                        .ok_or_else(|| {
                            boa_engine::JsError::from_opaque(JsValue::new(
                                "details object required",
                            ))
                        })?;

                    api.xml_http_request(details)
                        .map_err(|e| boa_engine::JsError::from_opaque(JsValue::new(e.to_string())))?;

                    Ok(JsValue::undefined())
                },
                api,
            );

            gm_object.function(xml_http_request, "xmlhttpRequest", 1);
        }

        {
            let api = gm_api.clone();
            let get_resource_url = NativeFunction::from_copy_closure_with_captures(
                move |_this, args, api, context| {
                    let name = args
                        .get(0)
                        .and_then(|v| v.as_string())
                        .ok_or_else(|| {
                            boa_engine::JsError::from_opaque(JsValue::new("name must be a string"))
                        })?
                        .to_std_string_escaped();

                    let url = api
                        .get_resource_url(&name)
                        .map_err(|e| boa_engine::JsError::from_opaque(JsValue::new(e.to_string())))?;

                    Ok(JsValue::new(url))
                },
                api,
            );

            gm_object.function(get_resource_url, "getResourceURL", 1);
        }

        {
            let api = gm_api.clone();
            let set_clipboard = NativeFunction::from_copy_closure_with_captures(
                move |_this, args, api, _context| {
                    let text = args
                        .get(0)
                        .and_then(|v| v.as_string())
                        .ok_or_else(|| {
                            boa_engine::JsError::from_opaque(JsValue::new("text must be a string"))
                        })?
                        .to_std_string_escaped();

                    api.set_clipboard(&text)
                        .map_err(|e| boa_engine::JsError::from_opaque(JsValue::new(e.to_string())))?;

                    Ok(JsValue::undefined())
                },
                api,
            );

            gm_object.function(set_clipboard, "setClipboard", 1);
        }

        // Build GM object
        let gm = gm_object.build();

        // Add to global
        global
            .set("GM", gm, true, context)
            .map_err(|e| Error::ScriptExecution(format!("Failed to inject GM API: {}", e)))?;

        debug!("GM API injected into JavaScript context");
        Ok(())
    }
}

/// Convert Boa JsValue to serde_json::Value
fn js_value_to_json(value: JsValue, context: &mut Context) -> JsResult<Value> {
    if value.is_null() || value.is_undefined() {
        Ok(Value::Null)
    } else if value.is_boolean() {
        Ok(Value::Bool(value.as_boolean().unwrap()))
    } else if value.is_number() {
        Ok(serde_json::json!(value.as_number().unwrap()))
    } else if value.is_string() {
        Ok(Value::String(
            value.as_string().unwrap().to_std_string_escaped(),
        ))
    } else if value.is_object() {
        let obj = value.as_object().unwrap();

        // Check if it's an array
        if obj.is_array() {
            let arr = boa_engine::object::JsArray::from_object(obj.clone())?;
            let len = arr.length(context)? as usize;
            let mut values = Vec::with_capacity(len);

            for i in 0..len {
                let element = arr.get(i, context)?;
                values.push(js_value_to_json(element, context)?);
            }

            Ok(Value::Array(values))
        } else {
            // Regular object
            let mut map = serde_json::Map::new();

            for key in obj.own_property_keys(context)? {
                if let Some(key_str) = key.as_string() {
                    let key_string = key_str.to_std_string_escaped();
                    if let Ok(value) = obj.get(key.clone(), context) {
                        map.insert(key_string, js_value_to_json(value, context)?);
                    }
                }
            }

            Ok(Value::Object(map))
        }
    } else {
        Ok(Value::Null)
    }
}

/// Convert serde_json::Value to Boa JsValue
fn json_to_js_value(value: Value, context: &mut Context) -> JsResult<JsValue> {
    match value {
        Value::Null => Ok(JsValue::null()),
        Value::Bool(b) => Ok(JsValue::new(b)),
        Value::Number(n) => Ok(JsValue::new(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => Ok(JsValue::new(s)),
        Value::Array(arr) => {
            let js_arr = boa_engine::object::JsArray::new(context);
            for (i, item) in arr.into_iter().enumerate() {
                let js_item = json_to_js_value(item, context)?;
                js_arr.set(i, js_item, context)?;
            }
            Ok(js_arr.into())
        }
        Value::Object(obj) => {
            let js_obj = boa_engine::object::JsObject::with_null_proto();
            for (key, val) in obj {
                let js_val = json_to_js_value(val, context)?;
                js_obj.set(key, js_val, true, context)?;
            }
            Ok(js_obj.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::UserscriptStorage;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn create_test_executor() -> ScriptExecutor {
        let temp_dir = tempdir().unwrap();
        let storage = Arc::new(UserscriptStorage::new(temp_dir.path().to_path_buf()).unwrap());
        let grants = vec![
            "GM_setValue".to_string(),
            "GM_getValue".to_string(),
            "GM_deleteValue".to_string(),
            "GM_listValues".to_string(),
            "GM_addStyle".to_string(),
            "GM_openInTab".to_string(),
            "GM_notification".to_string(),
            "GM_xmlhttpRequest".to_string(),
            "GM_getResourceURL".to_string(),
            "GM_setClipboard".to_string(),
        ];

        let gm_api = Arc::new(GmApi::new("test-script".to_string(), storage, grants));
        ScriptExecutor::new(gm_api).unwrap()
    }

    #[test]
    fn test_simple_execution() {
        let mut executor = create_test_executor();

        let script = r#"
            var x = 42;
            var y = x + 8;
        "#;

        executor.execute(script, "test").unwrap();
    }

    #[test]
    fn test_gm_set_get_value() {
        let mut executor = create_test_executor();

        let script = r#"
            GM.setValue('test_key', 'test_value');
            var result = GM.getValue('test_key');
        "#;

        executor.execute(script, "test").unwrap();
    }

    #[test]
    fn test_gm_list_values() {
        let mut executor = create_test_executor();

        let script = r#"
            GM.setValue('key1', 'value1');
            GM.setValue('key2', 'value2');
            var keys = GM.listValues();
        "#;

        executor.execute(script, "test").unwrap();
    }

    #[test]
    fn test_gm_info() {
        let mut executor = create_test_executor();

        let script = r#"
            var info = GM.info();
        "#;

        executor.execute(script, "test").unwrap();
    }

    #[test]
    fn test_error_handling() {
        let mut executor = create_test_executor();

        let script = r#"
            throw new Error('Test error');
        "#;

        let result = executor.execute(script, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_value_conversion() {
        let mut executor = create_test_executor();

        let script = r#"
            GM.setValue('number', 42);
            GM.setValue('string', 'hello');
            GM.setValue('boolean', true);
            GM.setValue('array', [1, 2, 3]);
            GM.setValue('object', {foo: 'bar'});

            var n = GM.getValue('number');
            var s = GM.getValue('string');
            var b = GM.getValue('boolean');
            var a = GM.getValue('array');
            var o = GM.getValue('object');
        "#;

        executor.execute(script, "test").unwrap();
    }
}
