fn main() {
    // 只有在 Windows 平台下才編譯 resource.rc
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_resource_file("resource.rc");
        res.compile().unwrap();
    }
}