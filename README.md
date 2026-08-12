# totp

A small native C++17 TOTP authenticator for a graphical Debian desktop.

Secrets are stored in the desktop Secret Service keyring through `libsecret`.
TOTP uses RFC 6238 with HMAC-SHA1, 30-second periods and 6 digits.

## Features

- Secret Service keyring storage
- Multiple accounts
- No secrets in command-line arguments
- Hidden secret entry
- RFC 6238 TOTP
- X11 clipboard via `xclip`
- Wayland clipboard via `wl-copy`
- Automatic clipboard clearing
- `--watch` mode
- `--plain` mode

## Dependencies

```bash
sudo apt install build-essential cmake pkg-config \
    libsecret-1-dev libssl-dev gnome-keyring xclip
```

For Wayland, also install:

```bash
sudo apt install wl-clipboard
```

## Build

```bash
cmake -S . -B build
cmake --build build -j"$(nproc)"
sudo cmake --install build
```

## Usage

```bash
totp test
totp add snappymail
totp snappymail
totp snappymail --watch
totp snappymail --plain
totp copy snappymail
totp copy snappymail --seconds 10
totp list
totp remove snappymail
```

The secret is entered interactively and is never accepted as a command-line argument.

## Files

- `src/main.cc` — process entry point and command dispatch
- `src/cli.*` — command implementations and help
- `src/keyring.*` — Secret Service persistence
- `src/totp.*` — RFC 6238 generation
- `src/base32.*` — Base32 decoding
- `src/clipboard.*` — X11/Wayland clipboard
- `src/terminal.*` — hidden terminal input
