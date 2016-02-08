
fn main() {
//    println!("cargo:rustc-link-search=/usr/lib/");
    println!("cargo:rustc-link-search=lib/");
    println!("cargo:rustc-link-lib=static=pwdb");
    println!("cargo:rustc-link-lib=static=tomcrypt");
    println!("cargo:rustc-link-lib=dylib=uuid");
}
