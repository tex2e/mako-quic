
# mako-http3

本レポジトリは [tex2e/mako-tls13](https://github.com/tex2e/mako-tls13) へ統合しました。
こちらのレポジトリは更新しません。



---

### Debug

Sample:
```
git clone https://github.com/cloudflare/quiche
cp quiche /opt/quiche
```

```
cd /opt/quiche
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


Wiresharkで復号する場合は、変数 `SSLKEYLOGFILE=./keylog.txt` をコマンド実行時に追加する。


