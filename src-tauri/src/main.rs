// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // started by a browser as native-messaging host: relay, no UI
    if anotherkeepass_lib::proxy::is_native_messaging() {
        anotherkeepass_lib::proxy::run();
        return;
    }
    anotherkeepass_lib::run();
}
