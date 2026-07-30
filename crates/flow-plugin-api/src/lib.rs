//! Developer API for Flow-Proxy plugins.
//!
//! A plugin is a `cdylib` that the proxy compiles at startup and loads with
//! `dlopen`. Everything crossing that boundary goes through `extern "C"` and
//! `#[repr(C)]` types, because Rust has no stable ABI: two crates built by
//! different compiler versions do not agree on the layout of a `String`, a
//! `Vec` or a trait object.
//!
//! Plugin authors do not touch any of that. Implement [`Plugin`] and invoke
//! [`flow_plugin!`]:
//!
//! ```ignore
//! use flow_plugin_api::prelude::*;
//!
//! #[derive(Default)]
//! struct Greeter;
//!
//! impl Plugin for Greeter {
//!     fn on_enable(&mut self, api: &Api) {
//!         api.info("greeter starting up");
//!     }
//!
//!     fn on_join(&mut self, api: &Api, player: &PlayerRef) {
//!         api.send_message(&player.username, "Welcome!");
//!     }
//!
//!     fn on_command(&mut self, api: &Api, player: &PlayerRef, command: &str) -> bool {
//!         if command == "hub" {
//!             api.connect_player(&player.username, "lobby");
//!             return true; // handled; do not forward to the backend
//!         }
//!         false
//!     }
//! }
//!
//! flow_plugin!(Greeter);
//! ```

use std::os::raw::c_void;

/// The ABI this crate speaks. The proxy refuses to load a plugin built against
/// a different one, which turns an undefined-behaviour crash into a clear
/// startup error.
pub const ABI_VERSION: u32 = 1;

// ---------------------------------------------------------------- FFI types

/// A borrowed UTF-8 string. Not NUL-terminated: the length is explicit, so
/// text containing a NUL byte cannot silently truncate.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FpStr {
    pub ptr: *const u8,
    pub len: usize,
}

impl FpStr {
    pub fn from_str(s: &str) -> Self {
        FpStr {
            ptr: s.as_ptr(),
            len: s.len(),
        }
    }

    pub const EMPTY: FpStr = FpStr {
        ptr: std::ptr::null(),
        len: 0,
    };

    /// # Safety
    /// The pointer must be valid for `len` bytes of UTF-8 for the duration of
    /// the call. The proxy guarantees this for the span of a callback only.
    pub unsafe fn as_str<'a>(&self) -> &'a str {
        if self.ptr.is_null() || self.len == 0 {
            return "";
        }
        let bytes = std::slice::from_raw_parts(self.ptr, self.len);
        std::str::from_utf8(bytes).unwrap_or("")
    }
}

/// A string owned by the host, released with [`FpHost::free_string`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FpOwnedStr {
    pub ptr: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl FpOwnedStr {
    pub const NULL: FpOwnedStr = FpOwnedStr {
        ptr: std::ptr::null_mut(),
        len: 0,
        capacity: 0,
    };
}

/// Event kinds delivered to `fp_event`.
pub mod event_kind {
    pub const JOIN: u32 = 1;
    pub const LEAVE: u32 = 2;
    pub const SWITCH: u32 = 3;
    pub const COMMAND: u32 = 4;
}

/// Log levels for [`FpHost::log`].
pub mod log_level {
    pub const ERROR: u32 = 1;
    pub const WARN: u32 = 2;
    pub const INFO: u32 = 3;
    pub const DEBUG: u32 = 4;
}

/// The functions the host offers to a plugin.
#[repr(C)]
pub struct FpHost {
    pub abi_version: u32,
    /// Opaque host state, passed back into every call.
    pub ctx: *mut c_void,
    pub log: extern "C" fn(*mut c_void, level: u32, message: FpStr),
    pub send_message: extern "C" fn(*mut c_void, player: FpStr, message: FpStr) -> bool,
    pub connect_player: extern "C" fn(*mut c_void, player: FpStr, server: FpStr) -> bool,
    pub kick_player: extern "C" fn(*mut c_void, player: FpStr, reason: FpStr) -> bool,
    pub player_count: extern "C" fn(*mut c_void) -> u32,
    /// Comma-separated player names, or names on one server when `server` is
    /// non-empty. The result must be released with `free_string`.
    pub player_names: extern "C" fn(*mut c_void, server: FpStr) -> FpOwnedStr,
    pub current_server: extern "C" fn(*mut c_void, player: FpStr) -> FpOwnedStr,
    pub free_string: extern "C" fn(FpOwnedStr),
}

/// One event. Unused fields are [`FpStr::EMPTY`].
#[repr(C)]
pub struct FpEvent {
    pub kind: u32,
    pub player: FpStr,
    pub uuid: FpStr,
    /// Join and switch: the server being joined. Leave: the last server.
    pub server: FpStr,
    /// Switch only: the server being left.
    pub from: FpStr,
    /// Command only: the command text, without the leading slash.
    pub text: FpStr,
}

/// Returned from `fp_event` to say a command was consumed.
pub const EVENT_HANDLED: u32 = 1;
pub const EVENT_IGNORED: u32 = 0;

// ------------------------------------------------------------- safe wrapper

/// The player an event concerns.
pub struct PlayerRef<'a> {
    pub username: &'a str,
    pub uuid: &'a str,
    pub server: &'a str,
}

/// Safe handle to the host.
pub struct Api {
    host: *const FpHost,
}

// The host guarantees the vtable outlives every plugin, and all host functions
// are internally synchronised.
unsafe impl Send for Api {}
unsafe impl Sync for Api {}

impl Api {
    /// # Safety
    /// `host` must point to a valid `FpHost` that outlives this `Api`.
    pub unsafe fn from_raw(host: *const FpHost) -> Self {
        Api { host }
    }

    fn host(&self) -> &FpHost {
        // Safe by the contract of `from_raw`.
        unsafe { &*self.host }
    }

    pub fn log(&self, level: u32, message: &str) {
        let host = self.host();
        (host.log)(host.ctx, level, FpStr::from_str(message));
    }

    pub fn error(&self, message: &str) {
        self.log(log_level::ERROR, message)
    }
    pub fn warn(&self, message: &str) {
        self.log(log_level::WARN, message)
    }
    pub fn info(&self, message: &str) {
        self.log(log_level::INFO, message)
    }
    pub fn debug(&self, message: &str) {
        self.log(log_level::DEBUG, message)
    }

    /// Sends a chat line. `player` may be `"ALL"`.
    pub fn send_message(&self, player: &str, message: &str) -> bool {
        let host = self.host();
        (host.send_message)(
            host.ctx,
            FpStr::from_str(player),
            FpStr::from_str(message),
        )
    }

    /// Moves a player to another backend.
    pub fn connect_player(&self, player: &str, server: &str) -> bool {
        let host = self.host();
        (host.connect_player)(host.ctx, FpStr::from_str(player), FpStr::from_str(server))
    }

    pub fn kick_player(&self, player: &str, reason: &str) -> bool {
        let host = self.host();
        (host.kick_player)(host.ctx, FpStr::from_str(player), FpStr::from_str(reason))
    }

    pub fn player_count(&self) -> u32 {
        let host = self.host();
        (host.player_count)(host.ctx)
    }

    /// Online player names. Pass `""` for every server.
    pub fn player_names(&self, server: &str) -> Vec<String> {
        let host = self.host();
        let owned = (host.player_names)(host.ctx, FpStr::from_str(server));
        let text = self.take_owned(owned);
        if text.is_empty() {
            return Vec::new();
        }
        text.split(',').map(|s| s.trim().to_string()).collect()
    }

    /// The backend a player is currently on, if they are online.
    pub fn current_server(&self, player: &str) -> Option<String> {
        let host = self.host();
        let owned = (host.current_server)(host.ctx, FpStr::from_str(player));
        let text = self.take_owned(owned);
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    fn take_owned(&self, owned: FpOwnedStr) -> String {
        if owned.ptr.is_null() {
            return String::new();
        }
        // Copy out before handing the allocation back: it was allocated by the
        // host, so only the host may free it.
        let text = unsafe {
            let bytes = std::slice::from_raw_parts(owned.ptr, owned.len);
            String::from_utf8_lossy(bytes).into_owned()
        };
        let host = self.host();
        (host.free_string)(owned);
        text
    }
}

/// What a plugin implements.
pub trait Plugin: Send + 'static {
    /// Called once when the plugin is loaded.
    fn on_enable(&mut self, _api: &Api) {}
    /// Called when the proxy shuts down.
    fn on_disable(&mut self, _api: &Api) {}
    fn on_join(&mut self, _api: &Api, _player: &PlayerRef) {}
    fn on_leave(&mut self, _api: &Api, _player: &PlayerRef) {}
    fn on_switch(&mut self, _api: &Api, _player: &PlayerRef, _from: &str, _to: &str) {}
    /// Return `true` to consume the command so it never reaches the backend.
    fn on_command(&mut self, _api: &Api, _player: &PlayerRef, _command: &str) -> bool {
        false
    }
}

/// Generates the `extern "C"` entry points for a [`Plugin`] implementation.
///
/// Every callback is wrapped in `catch_unwind`: a panic unwinding across the
/// FFI boundary is undefined behaviour, so a buggy plugin must be contained
/// rather than allowed to take the proxy with it.
#[macro_export]
macro_rules! flow_plugin {
    ($ty:ty) => {
        static __FP_PLUGIN: ::std::sync::Mutex<Option<$ty>> = ::std::sync::Mutex::new(None);
        static __FP_API: ::std::sync::Mutex<Option<$crate::Api>> = ::std::sync::Mutex::new(None);

        #[no_mangle]
        pub extern "C" fn fp_abi_version() -> u32 {
            $crate::ABI_VERSION
        }

        #[no_mangle]
        pub extern "C" fn fp_init(host: *const $crate::FpHost) -> u32 {
            let result = ::std::panic::catch_unwind(|| {
                if host.is_null() {
                    return 1;
                }
                let api = unsafe { $crate::Api::from_raw(host) };
                let mut plugin = <$ty as ::std::default::Default>::default();
                plugin.on_enable(&api);

                *__FP_PLUGIN.lock().unwrap() = Some(plugin);
                *__FP_API.lock().unwrap() = Some(api);
                0
            });
            result.unwrap_or(2)
        }

        #[no_mangle]
        pub extern "C" fn fp_event(event: *const $crate::FpEvent) -> u32 {
            let result = ::std::panic::catch_unwind(|| {
                if event.is_null() {
                    return $crate::EVENT_IGNORED;
                }
                let event = unsafe { &*event };

                let api_guard = __FP_API.lock().unwrap();
                let Some(api) = api_guard.as_ref() else {
                    return $crate::EVENT_IGNORED;
                };
                let mut plugin_guard = __FP_PLUGIN.lock().unwrap();
                let Some(plugin) = plugin_guard.as_mut() else {
                    return $crate::EVENT_IGNORED;
                };

                let player = $crate::PlayerRef {
                    username: unsafe { event.player.as_str() },
                    uuid: unsafe { event.uuid.as_str() },
                    server: unsafe { event.server.as_str() },
                };

                match event.kind {
                    $crate::event_kind::JOIN => {
                        plugin.on_join(api, &player);
                        $crate::EVENT_IGNORED
                    }
                    $crate::event_kind::LEAVE => {
                        plugin.on_leave(api, &player);
                        $crate::EVENT_IGNORED
                    }
                    $crate::event_kind::SWITCH => {
                        let from = unsafe { event.from.as_str() };
                        plugin.on_switch(api, &player, from, player.server);
                        $crate::EVENT_IGNORED
                    }
                    $crate::event_kind::COMMAND => {
                        let text = unsafe { event.text.as_str() };
                        if plugin.on_command(api, &player, text) {
                            $crate::EVENT_HANDLED
                        } else {
                            $crate::EVENT_IGNORED
                        }
                    }
                    _ => $crate::EVENT_IGNORED,
                }
            });
            result.unwrap_or($crate::EVENT_IGNORED)
        }

        #[no_mangle]
        pub extern "C" fn fp_shutdown() {
            let _ = ::std::panic::catch_unwind(|| {
                let api_guard = __FP_API.lock().unwrap();
                let mut plugin_guard = __FP_PLUGIN.lock().unwrap();
                if let (Some(api), Some(plugin)) = (api_guard.as_ref(), plugin_guard.as_mut()) {
                    plugin.on_disable(api);
                }
                *plugin_guard = None;
            });
        }
    };
}

pub mod prelude {
    pub use crate::{flow_plugin, Api, Plugin, PlayerRef};
}
