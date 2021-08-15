
# mako-http3

実装中



---

### Debug

Sample:
```
git clone https://github.com/cloudflare/quiche
cp quiche /opt/quiche
```

サーバ側：
```
cargo run --manifest-path=tools/apps/Cargo.toml --bin quiche-server -- \
      --cert tools/apps/src/bin/cert.crt \
      --key tools/apps/src/bin/cert.key
```

クライアント側：
```
cargo run --manifest-path=tools/apps/Cargo.toml --bin quiche-client -- https://localhost:4433/ --no-verify
```




