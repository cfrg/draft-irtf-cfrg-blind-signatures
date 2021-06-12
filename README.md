# RSA Blind Signatures

This is the working area for the individual Internet-Draft, "RSA Blind Signatures".

* [Editor's Copy](https://cfrg.github.io/draft-irtf-cfrg-blind-signatures/#go.draft-irtf-cfrg-rsa-blind-signatures.html)
* [Individual Draft](https://tools.ietf.org/html/draft-irtf-cfrg-rsa-blind-signatures)
* [Compare Editor's Copy to Individual Draft](https://cfrg.github.io/draft-irtf-cfrg-blind-signatures/#go.draft-irtf-cfrg-rsa-blind-signatures.diff)

## Building the Draft

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

This requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/master/doc/SETUP.md).

## Implementations

| Implementation                                                                                  | Language | Dependencies         |
| ----------------------------------------------------------------------------------------------- | :------- | :------------------- |
| [**Reference**](https://github.com/chris-wood/draft-wood-cfrg-blind-signatures/tree/master/poc) | Sage     | Sage                 |
| [blind-rsa-signatures](https://github.com/jedisct1/blind-rsa-signatures)                        | C        | OpenSSL or BoringSSL |
| [zig-blind-rsa-signatures](https://github.com/jedisct1/zig-blind-rsa-signatures)                | Zig      | OpenSSL or BoringSSL |
| [rust-blind-rsa-signatures](https://github.com/jedisct1/rust-blind-rsa-signatures)              | Rust     | -                    |

## Contributing

See the
[guidelines for contributions](https://github.com/cfrg/draft-irtf-cfrg-blind-signatures/blob/master/CONTRIBUTING.md).
