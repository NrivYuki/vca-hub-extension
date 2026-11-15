# vca-hub の拡張

vca-hub に機能を加える拡張を置くリポジトリである。

| フォルダ | 中身 |
|---|---|
| `oldp/` | OLDP([Optical Lab Device Protocol](https://github.com/NrivYuki/optical-lab-device-protocol))の通信方式と、機器のペアリングの管理画面 |
| `tests/` | vca-hub を通した疎通のテスト |
| `tools/verify-device.js` | 機器の側の実装を vca-hub とつなぎ、規格の流れを一通り確かめる道具 |
| `tools/attack-uart.js` | 機器と vca-hub の間の UART の線に割り込む相手を置き、フレームの差し込み・書き換え・送り直し・捨てることに対する動作を確かめる道具 |
| `tools/attack-tcp.js` | 同じことを TCP の線で行う道具。線の上に平文や静的な公開鍵が現れないこと、なりすましのホストと機器を断ることも確かめる |
| `tools/fuzz-hub.js` | vca-hub の OLDP の待ち受けに乱数で作った入力を送り、止まらないこと・メモリが増え続けないこと・管理画面のペアリングを外から操作できないことを確かめる道具 |

## 必要なもの

| もの | 置き場所と用途 |
|---|---|
| Node.js 22 以上 | テストと `verify-device.js` を動かす(vca-hub の中で動くときは、vca-hub が使う Node.js) |
| [vca-hub](https://github.com/NrivYuki/vca-hub) | 隣のフォルダ(`../vca-hub`)か、環境変数 `OLDP_VCA_HUB` で指定した場所。テストと `verify-device.js` で使う |
| OLDP の参照実装([optical-lab-device-protocol-reference](https://github.com/NrivYuki/optical-lab-device-protocol-reference)) | 隣のフォルダ(`../optical-lab-device-protocol-reference`)か、環境変数 `OLDP_REFERENCE` で指定した場所。`oldp/` が規格の処理に使う(読み込みは `oldp/reference.js`) |

## OLDP の通信方式(oldp/)

vca-hub の `config.json` に、次のように書く。拡張の名前と通信方式の名前は `oldp` である。

```json
{
  "extensionsDir": "<このフォルダ>",
  "extensions": { "oldp": true },
  "listeners": [{ "name": "新しい規格の機器", "port": 33520, "protocol": "oldp" }]
}
```

知らない機器が接続すると、管理画面の「機器のペアリング」に、ペアリング待ちとして表示される。フィンガープリントを機器の画面と見比べ、同じであれば「信じる」を選ぶ。

ホストの秘密鍵は、vca-hub のデータのフォルダ(`ext/oldp/host-key.json`)に保存する。Windows では DPAPI で暗号化するので、同じ PC の同じユーザーでなければ復号できない。ほかの OS では暗号化せず、ファイルの権限を所有者だけにする。暗号化していない形で保存されていた鍵は、読み込んだときに暗号化して書き直す。

シリアルの機器を TCP へ中継してつなぐときは、待ち受けの設定に `"settings": { "transport": "uart" }` を書く。機器を PC と直結して、アドレスがリンクローカル(169.254.0.0/16)になるときは、vca-hub の `allow` に `169.254.0.0/16` を加える。

規格の拡張(規格の 11 章)は、次のどちらかの方法で加える。

- `oldp/vendors` に `.js` のファイルを置く。
- 別の vca-hub の拡張から、`require('../oldp').vendor({ namespace, handle })` で登録する。

登録した名前空間は、`EXT=` で機器に知らせる。待ち受けの `settings` の `require` に書いた名前空間は、`REQUIRE=` で機器に対応を求める。標準の拡張 OLDPKEY(機器の鍵の交換)は、`oldp/vendors/oldpkey.js` にある。

## テスト

```
node --test tests/integration.test.js
```

vca-hub が見つからなければ、テストを飛ばす。

`tools/verify-device.js` は、機器の側の実装を vca-hub とつないで、次の流れを確かめる。ペアリング、PUT、同じ PUT の 2 度目、GET、RESULT、TIME、PING、INFO、AVAIL、受けられない値、1440 点の玉型、ペアリングの解除である。H8 の基板では、標準の拡張 OLDPKEY による鍵の交換も確かめる。

機器の側には、参照実装の C の模擬機器か H8 の基板を使う。組み立てと基板の準備は、参照実装の README に従う。`COM3` は、基板をつないだシリアルポートの例である。

```
node tools/verify-device.js sim
node tools/verify-device.js h8 COM3
node tools/verify-device.js h8lan COM3
```

基板のシリアルの速度を変えてあるとき(基板の `baud` コマンド)は、3 つ目にその速度を渡す。4 つ目に PC の側の速度を渡すと、PC の側だけをその速度にする(規格の一覧にない速度を試すため)。

```
node tools/verify-device.js h8 COM3 57600
```

`tools/attack-uart.js` は、機器と vca-hub の UART の待ち受けの間に中継を挟み、線に割り込む相手と同じことを行う(電気の層の攻撃は扱わない)。

```
node tools/attack-uart.js sim
node tools/attack-uart.js h8 COM3
```

`tools/attack-tcp.js` は、TCP の待ち受けの前に中継を挟んで同じことを行う。H8 の基板では LAN を使う(基板の `ip` コマンドで、この PC のアドレスとポート 33520 を設定しておく)。

```
node tools/attack-tcp.js sim
node tools/attack-tcp.js h8lan COM3
```

`tools/fuzz-hub.js` は、vca-hub をこのプロセスの中で動かし、ハンドシェイクの前の壊れた入力、ペアリングした機器からの形の崩れたメッセージ、組み立て途中のメッセージによるメモリの増え方、ハンドシェイクを始めない接続による締め出し、管理画面の操作の制限を確かめる。引数は回数の倍率である。

```
node --expose-gc tools/fuzz-hub.js 1
```

## 確かめた環境

Windows 10 Pro(10.0.19045)、Node.js 24.20.0、Windows PowerShell 5.1(DPAPI)で確かめた。機器の側の環境は、参照実装の README に示す。

## ライセンス

MIT(`LICENSE`)
