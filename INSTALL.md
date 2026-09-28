# Installing nano-vanity

Two ways: grab a prebuilt binary, or build from source. Building from source
on Termux takes a few minutes; the prebuilt binary is instant.

Releases are published automatically for three targets:

| Target | File | Runs on |
|---|---|---|
| `aarch64-linux-android` | `nano-vanity-android-arm64` | Termux on Android (64-bit) |
| `x86_64-unknown-linux-gnu` | `nano-vanity-linux-amd64` | Ubuntu, Debian, Fedora, x86_64 |
| `x86_64-pc-windows-msvc` | `nano-vanity-windows-amd64.exe` | Windows x64 |

---

## Prebuilt binary

### Termux (Android, aarch64)

```sh
pkg install wget
wget https://github.com/tyyuuii/nano-vanity/releases/latest/download/nano-vanity-android-arm64
mv nano-vanity-android-arm64 $PREFIX/bin/nano-vanity
chmod +x $PREFIX/bin/nano-vanity
```

`$PREFIX/bin` is already on your `PATH`, so this is now just `nano-vanity`.

### Ubuntu / Debian (x86_64)

```sh
wget https://github.com/tyyuuii/nano-vanity/releases/latest/download/nano-vanity-linux-amd64
sudo install -m 755 nano-vanity-linux-amd64 /usr/local/bin/nano-vanity
```

### Windows (x64)

Download `nano-vanity-windows-amd64.exe` from the releases page and run it. The
web UI opens at <http://127.0.0.1:8787/>.

### Verify what you downloaded

Every release ships a `SHA256SUMS` file:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

This tool prints wallet seeds and private keys. A binary that has been tampered
with is a wallet compromise, so if you did not build it yourself, check it.

---

## Build from source

Needs a stable Rust toolchain. Only two dependencies: `blake2` and
`curve25519-dalek`. No C libraries, no `openssl-sys`.

```sh
git clone https://github.com/tyyuuii/nano-vanity
cd nano-vanity
cargo build --release
./target/release/nano-vanity --help
```

### Termux notes

- Install Rust with `pkg install rust`. **Do not use `rustup`** — it has no
  `aarch64-linux-android` toolchain and will not work.
- Limit build parallelism or Android's low-memory killer can kill `rustc`:

  ```sh
  mkdir -p .cargo
  printf '[build]\njobs = 2\n' > .cargo/config.toml
  cargo build --release
  ```

- For long grinds, keep the screen awake with `termux-wake-lock`.
- No proot or chroot required.

### Ubuntu notes

```sh
sudo apt install build-essential
cargo build --release
sudo install -m 755 target/release/nano-vanity /usr/local/bin/nano-vanity
```

---

## Termux extras: `install.sh` and the `Nanvin` launcher

`./install.sh` is **Termux-specific**. It builds the release binary, copies it
into `$PREFIX/bin`, and generates a `Nanvin` launcher that starts the web
server, waits for it to be ready, and opens your browser.

```sh
./install.sh              # build, install, create the launcher
./install.sh --uninstall  # remove both, leave sources alone
```

Afterwards:

```sh
Nanvin              # start the server and open the browser
Nanvin -p 9000      # use a different port
Nanvin --no-open    # start the server without launching a browser
Nanvin --stop       # stop a running server
```

The launcher exists because Termux has no desktop session, so there is nothing
to auto-open a browser against; it does that part for you. On Ubuntu and
Windows, just run `nano-vanity --web` and visit the printed URL.

---

## Web UI and seeds — please read

`--web` serves a UI that shows **wallet seeds and private keys in plain text**.
It therefore binds to `127.0.0.1` only, and prints a warning if you bind it
anywhere else:

```sh
nano-vanity --web                      # loopback only (default)
nano-vanity --web --bind 0.0.0.0:8787  # anyone who can reach the port can read your keys
```

Treat any machine that has run this as sensitive. The address of any result
should be verified in a wallet before you send funds to it, and a brand-new
account must be opened with a small send from another account before it can
receive directly.

---

## Quick start

Find a five-character prefix, searching seeds so the result lands on account 0
(so importing the seed is the entire job):

```sh
nano-vanity 1test --grind
```

Find four matching addresses from one seed, reproducibly:

```sh
nano-vanity 1111 -n 4
```

Reproduce an earlier run exactly:

```sh
nano-vanity 1111 -s <the seed that was printed>
```

Check a seed and account index against a wallet that disagrees with you:

```sh
nano-vanity --derive <SEED> --index 0
```

Run the web UI:

```sh
Nanvin          # Termux
nano-vanity --web
```
