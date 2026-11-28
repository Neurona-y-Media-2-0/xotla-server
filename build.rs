// build.rs
fn main() {
    println!("cargo:rerun-if-changed=src/modules/enterprise/admin_tokens.html");
    println!("cargo:rerun-if-changed=src/modules/scanner/db_viewer.html");
    println!("cargo:rerun-if-changed=src/modules/policy/demo_phishing.html");
}
