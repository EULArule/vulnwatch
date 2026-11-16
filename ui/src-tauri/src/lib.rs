//! The app shell. The web UI calls one command, `rpc`, which is the same JSON API the server
//! exposes over HTTP. On Android the Kotlin side (WorkManager worker, foreground service) calls
//! into the same process-wide core through JNI, so background checks and the UI share one database.

use std::{
    path::Path,
    sync::{Arc, OnceLock},
};

use serde_json::{json, Value};
use tauri::Manager;
use vulnwatch_core::Core;

static CORE: OnceLock<Arc<Core>> = OnceLock::new();

fn open_core(dir: &Path, mobile: bool) -> Result<Arc<Core>, String> {
    if let Some(core) = CORE.get() {
        return Ok(core.clone());
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let core = Arc::new(Core::open(dir, mobile).map_err(|e| format!("{e:#}"))?);
    Ok(CORE.get_or_init(|| core).clone())
}

fn core() -> Result<Arc<Core>, String> {
    CORE.get().cloned().ok_or_else(|| "vulnwatch is still starting".to_string())
}

fn handle(method: &str, params: Value) -> Result<Value, String> {
    if let Some(what) = method.strip_prefix("android.") {
        // The few that take something (a file to save or share) get it as JSON.
        let arg = if params.is_null() { String::new() } else { params.to_string() };
        return host::call(what, &arg);
    }
    let result = core()?.call(method, params).map_err(|e| format!("{e:#}"))?;
    // Things only the host can do: show notifications on this device, and re-plan background work.
    match method {
        "poll" => host::notify(&result["notifications"]),
        "notify.test" => host::notify(&json!([result["notification"]])),
        "settings.set" | "data.import" => {
            let _ = host::call("reschedule", "");
        }
        _ => {}
    }
    Ok(result)
}

#[tauri::command]
async fn rpc(method: String, params: Option<Value>) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || handle(&method, params.unwrap_or(Value::Null)))
        .await
        .map_err(|e| e.to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // On Android the activity has already opened the core (see MainActivity/Native.kt).
            if CORE.get().is_none() {
                let dir = app.path().app_data_dir()?;
                open_core(&dir, cfg!(mobile))?;
            }
            host::start();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![rpc])
        .run(tauri::generate_context!())
        .expect("error while running vulnwatch");
}

/// Desktop: there is no OS scheduler to lean on, so check in a thread while the window is open.
#[cfg(not(target_os = "android"))]
mod host {
    use super::*;

    pub fn call(what: &str, _arg: &str) -> Result<Value, String> {
        Ok(match what {
            "state" => json!({ "notifications": true, "battery_exempt": true, "exact_alarms": true }),
            _ => Value::Null,
        })
    }

    pub fn notify(_list: &Value) {}

    pub fn start() {
        std::thread::spawn(|| loop {
            let Ok(core) = core() else { return };
            // Turned off in settings: keep looking, so turning it back on needs no restart.
            if core.settings().check_every().is_none() {
                std::thread::sleep(std::time::Duration::from_secs(15));
                continue;
            }
            core.poll();
            std::thread::sleep(core.settings().check_every().unwrap_or(std::time::Duration::from_secs(60)));
        });
    }
}

#[cfg(target_os = "android")]
mod host {
    use std::panic::catch_unwind;

    use jni::{
        objects::{GlobalRef, JClass, JString, JValue},
        sys::{jboolean, jstring},
        JNIEnv, JavaVM,
    };

    use super::*;

    static VM: OnceLock<JavaVM> = OnceLock::new();
    /// `app.vulnwatch.Native`. Cached because native threads cannot look up app classes by name.
    static NATIVE: OnceLock<GlobalRef> = OnceLock::new();

    /// Call `Native.bridge(what, arg)` on the Kotlin side; it answers with JSON.
    pub fn call(what: &str, arg: &str) -> Result<Value, String> {
        let (Some(vm), Some(native)) = (VM.get(), NATIVE.get()) else {
            return Err("the Android side is not ready".into());
        };
        let mut env = vm.attach_current_thread().map_err(|e| e.to_string())?;
        let run = |env: &mut JNIEnv| -> jni::errors::Result<String> {
            let what = env.new_string(what)?;
            let arg = env.new_string(arg)?;
            let class: &JClass = native.as_obj().into();
            let out = env
                .call_static_method(
                    class,
                    "bridge",
                    "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(&what), JValue::Object(&arg)],
                )?
                .l()?;
            if out.is_null() {
                return Ok("null".into());
            }
            Ok(env.get_string(&JString::from(out))?.into())
        };
        match run(&mut env) {
            Ok(text) => Ok(serde_json::from_str(&text).unwrap_or(Value::Null)),
            Err(e) => {
                let _ = env.exception_clear();
                Err(format!("Android call {what} failed: {e}"))
            }
        }
    }

    pub fn notify(list: &Value) {
        if list.as_array().is_some_and(|l| !l.is_empty()) {
            let _ = call("notify", &list.to_string());
        }
    }

    pub fn start() {}

    fn to_java(env: &mut JNIEnv, text: &str) -> jstring {
        env.new_string(text).map(JString::into_raw).unwrap_or(std::ptr::null_mut())
    }

    /// `Native.init(dataDir)`: open the database. Called by the activity before the webview
    /// exists, and by the worker/service/boot receiver when Android starts the process without UI.
    #[no_mangle]
    pub extern "system" fn Java_app_vulnwatch_Native_init<'l>(
        mut env: JNIEnv<'l>,
        class: JClass<'l>,
        dir: JString<'l>,
    ) -> jboolean {
        if let Ok(vm) = env.get_java_vm() {
            let _ = VM.set(vm);
        }
        if let Ok(global) = env.new_global_ref(&class) {
            let _ = NATIVE.set(global);
        }
        let dir: String = match env.get_string(&dir) {
            Ok(d) => d.into(),
            Err(_) => return 0,
        };
        let opened = catch_unwind(|| open_core(Path::new(&dir), true).is_ok()).unwrap_or(false);
        u8::from(opened)
    }

    /// `Native.poll()`: one check. Returns `{new, errors, skipped, notifications}` as JSON.
    #[no_mangle]
    pub extern "system" fn Java_app_vulnwatch_Native_poll<'l>(mut env: JNIEnv<'l>, _class: JClass<'l>) -> jstring {
        let out = catch_unwind(|| match core() {
            Ok(core) => {
                let report = core.poll();
                json!({
                    "new": report.alerts.len(),
                    "errors": report.errors,
                    "skipped": report.skipped,
                    "notifications": report.notifications,
                })
            }
            Err(e) => json!({ "new": 0, "errors": [e], "skipped": true, "notifications": [] }),
        })
        .unwrap_or_else(|_| json!({ "new": 0, "errors": ["the check crashed"], "skipped": true, "notifications": [] }));
        to_java(&mut env, &out.to_string())
    }

    /// `Native.config()`: what the scheduler needs to know, `{background, interval_minutes, since_last}`.
    #[no_mangle]
    pub extern "system" fn Java_app_vulnwatch_Native_config<'l>(mut env: JNIEnv<'l>, _class: JClass<'l>) -> jstring {
        let out = catch_unwind(|| match core() {
            Ok(core) => {
                let s = core.settings();
                // Checking turned off altogether is, to the scheduler, background mode "off".
                let background = if s.interval_minutes == 0 { "off" } else { s.background.as_str() };
                json!({ "background": background, "interval_minutes": s.interval_minutes, "since_last": core.since_last_check() })
            }
            Err(_) => json!({ "background": "periodic", "interval_minutes": 15 }),
        })
        .unwrap_or_else(|_| json!({ "background": "periodic", "interval_minutes": 15 }));
        to_java(&mut env, &out.to_string())
    }

}
