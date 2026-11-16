# Mildly Server

The personal server the Mildly app pairs with: a Rust engine (`mildly-server`) that runs the
user's containers on Docker or Podman, answers the app over a sealed API, and serves sites
under a free or own address through Caddy. The app lives in a separate repository
(`sashinovsky/mildlydev`, folder `app/`); its `app/src/services/live/server.ts`,
`server-wire.ts` and `server-tools.ts` are the other side of everything here.

- `docs/SERVER.md` — trust model, pairing, the API, containers, addresses, install, the order
  of work and what is still undecided. **Read it before changing the engine.**
- `LICENSE.md` — closed source: permission to use only. Never add an open-source licence or
  licence headers that say otherwise.

## Rules

1. **The wire format is shared with the app.** `src/crypto.rs` must produce the same bytes as
   the app's WebCrypto code; method names, params and answers in `src/rpc.rs` follow the
   app's `ServerService` contract. Change both sides together, and keep `docs/SERVER.md`
   (section 4) in step.
2. **Error codes, not sentences.** The engine answers `{code}`; the app turns each code into a
   translated sentence. A new code needs a sentence in the app.
3. **Apps already on the machine are the user's.** Containers without `ai.mildly.*` labels can
   be listed, read, inspected, joined, started, stopped and opened in a shell by the owner,
   never written into, run in, recreated or removed.
4. **Secrets stay on the server.** The deSEC token and the server key live in `state.json`
   (0600); nothing returns environment values of containers.
5. Comments say what the code is for, not what changed.

## Commands

```bash
cargo build                                  # debug build
cargo run -- run --config ./config.toml      # an empty config works; set data_dir somewhere writable
cargo run -- pair --config ./config.toml     # a fresh code from the running engine
```

There is no test suite. Before saying something works: `cargo build` without warnings, then
run the engine against a real Docker and drive it from the app (`npm run dev:live` in the
app repository; in dev mode `window.__app` is the store).

Releases: bump `version` in `Cargo.toml`, push a tag `v<version>`; `.github/workflows/build.yml`
publishes the binaries and `install.sh`.
