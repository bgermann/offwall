# Building OFFWall

OFFWall is provided by the cargo crate offwall.
Rust version 1.22.0 is minimally required to build it.
Building the crate on a system that has rustc and cargo available is as easy as `cargo build`.
Installing to the local cargo path takes a `cargo install`.

The crate has one optional feature: tls.
This feature needs the OpenSSL or LibreSSL library installed on the system.
For more information please consult the [openssl crate's documentation](https://crates.io/crates/openssl).
If you want to enable TLS, please use the `--features tls` option appended to the aforementioned commands.

## Prerequisites for cross compilation

The production target system for OFFWall is Solaris 10 (SPARC64).
A compatible cross linker is required to build, which is provided by the [cross crate](https://crates.io/crates/cross).
It also includes an OpenSSL installation, so you do not have to care about installing it.

You should use a x86_64 GNU/Linux build system with cross.
It depends on the `rustup` toolchain manager and `docker`.
Be sure to add the building system user to the docker group.

cross is installed via `cargo install cross`.

## Packaging for Solaris 10

It is assumed that you have cross installed and the docker daemon is running.
[The Heirloom Packaging Tools}(http://heirloom.sourceforge.net/pkgtools.html)
and a make implementation are also required.
At least make, pkgmk, rustup, docker and cross have to be in $PATH.
Build the Solaris 10 SVR4 package by simply running `make`.
You will find the package at the new directory offwall.
You can `make offwall.pkg` a container with pkgtrans available.

## Installing on Solaris 10

You can download Solaris SVR4 packages from
[GitHub Releases](https://github.com/bgermann/offwall/releases) and install them with pkgadd.
If you build the package yourself, possibly you get a checksum error
because the upstream Heirloom Packaging Tools depend on a long's size
being 32 bit for computing the checksums. You should install a 32-bit version.
If that is not possible, pkgadd has an undocumented -C flag to deactivate checksum checks.
Or you can [patch](https://github.com/eunuchs/heirloom-project/pull/1) and build from source.
