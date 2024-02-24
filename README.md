# fake-oauth

[![Latest Version][crates-badge]][crates.io]
![Apache 2.0 OR MIT licensed][license-badge]

[crates.io]: https://crates.io/crates/fake-oauth
[crates-badge]: https://img.shields.io/crates/v/fake-oauth.svg
[license-badge]: https://img.shields.io/badge/license-Apache2.0%2FMIT-blue.svg

A fake OAuth implementation good for testing environment. Fake users with
customized claims can be defined to test your application with different
profile or to reproduce the production environment without compromising the
security of your systems.

## Install

If cargo is installed, fake-oauth can be installed with it:

```
$ cargo install fake-oauth
```

Alternatively you can run fake-oauth docker image using the following command:

```
$ docker run -p 7160:7160 ghcr.io/mattiapenati/fake-oauth
```

## Configuration

It is quite easy to configure the fake-oauth. The behaviour of the server can
be customized using the enviroment variables:

- `FAKE_OAUTH_ADDR`: the listening address of the server (default:
  `[::1]:7160`).
- `FAKE_OAUTH_ISSUER`: the server address, it can be changed if the service is
  reachable using an address different from the default one
  `http://localhost:{local_port}`.
- `FAKE_OAUTH_USERS`: the path of the toml file used to configure the users
  (default: `/var/lib/fake-oauth/users.toml`).

File `users.toml` contains the definition of the user, each user is identified
by its id (`sub` field of access token) and you can define its metadata used to
populate the token claims. Look at `assets/users.tom` file for an example.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT
license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
