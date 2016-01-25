
fn main() {
    println!("cargo:rustc-link-search=lib/");
    println!("cargo:rustc-link-lib=static=pwdb");
    println!("cargo:rustc-link-lib=static=tomcrypt");
}
