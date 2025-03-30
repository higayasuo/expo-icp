# セットアップ手順

英語版は[こちら](setup.md)です。

## 必要な環境

- Node.js バージョン 18 以上が必要です

## Expo Go のインストール

お使いの端末に「Expo Go」アプリをインストールしてください：

- iPhone/iPad をお使いの方：App Store からインストール
- Android をお使いの方：Google Play Store からインストール

## mkcert のインストール

mkcert は、ローカル開発環境で HTTPS 通信を簡単に実現するためのツールです。
mkcert のインストール方法と設定手順を説明します。

### macOS でのインストール

```bash
brew install mkcert
brew install nss # Firefoxを使用する場合は必要
```

### ルート認証局の設定

```bash
mkcert -install
```

### ルート証明書の場所確認

```bash
mkcert -CAROOT
```

### iOS でのルート証明書のインストール

- rootCA.pem ファイルを iOS デバイスに送信
- 設定アプリで「プロファイルがダウンロードされました」からインストール
- 設定 → 一般 → 情報 → 証明書信頼設定で mkcert 証明書を有効化

### Android でのルート証明書のインストール

- rootCA.pem ファイルを Android デバイスに転送
- 設定 → セキュリティ → その他 → ストレージからインストール
- CA 証明書として選択してインストール

**重要な注意点**

- Firefox を使用する場合は必ず nss のインストールが必要
- 作成された鍵ファイルは絶対に共有しない
- Android は、機種によって、ルート証明書のインストール方法が異なる場合がある

## プロジェクトのダウンロード

以下のコマンドで、プロジェクトをダウンロードし、プロジェクトフォルダに移動します：

```bash
git clone https://github.com/higayasuo/<REPOSITORY_NAME>
cd <RESPOSITORY_NAME>
```

<REPOSITORY_NAME>は、このプロジェクトのリポジトリ名で置き換えてください。

## Rust と ICP の開発ツールのセットアップ

Rust と ICP の開発ツールをセットアップする手順を説明します。

### コマンド実行

以下のコマンドを実行して、Rust と ICP の開発ツールをセットアップします：

```bash
./scripts/setup.sh
```

### セットアップ確認

セットアップが正常に完了したかを確認するため、以下のコマンドを実行します：

```bash
rustc -V
dfx -V
```

両方のコマンドがバージョン情報を表示すれば、セットアップは成功です。

**注意点**：

- バージョン確認時は「V」は必ず大文字で入力してください
- セットアップには数分かかる場合があります
- セットアップ終了後、`exec $SHELL -l`を実行して、シェルのパスを更新してください

## サブプロジェクトのセットアップ

expo-starter プロジェクトには、いくつかのサブプロジェクトで構成されています。
下記のコマンドで、サブプロジェクトのセットアップを行います：

```bash
npm run setup
```

## 固定 IP アドレスの設定

PC の開発サーバーにスマートフォンからアクセスするために、固定の IP アドレスを設定します。
これにより、PC を再起動しても IP アドレスが変更されず、安定した接続が可能になります。

### macOS

1. アップルメニューから「システム設定」を開きます

2. サイドバーで「ネットワーク」をクリックします

3. 使用中のネットワーク接続（Wi-Fi または Ethernet）を選択し、「詳細」をクリックします

4. 「TCP/IP」タブを開きます

5. 「IPv4 を構成」のプルダウンメニューから「DHCP サーバを使用(アドレスは手入力)」を選択し、以下の情報を入力します：

   - IP アドレス

     - DHCP の動的割り当てと被りにくい、192.168.0.200-192.168.0.254 の範囲で設定するのがおすすめです。
       例えば、192.168.0.210 を使うといいでしょう。

   - もし、192.168.0.210 以外のアドレスを使った場合は、下記のファイルの IP アドレスを書き換えてください
     - [../src/frontend/app/+html.tsx](../src/frontend/app/+html.tsx)
     - [../src/frontend/icp-assets/.ic-assets.json5](../src/frontend/icp-assets/.ic-assets.json5)
     - [../src/ii-integration/assets/.ic-assets.json5](../src/ii-integration/assets/.ic-assets.json5)

## サーバー証明書の作成手順

先ほど設定した固定 IP アドレスに HTTPS で通信するために、サーバー証明書を作成します。

### 準備

```bash
mkdir .mkcert
cd .mkcert
```

証明書保管用の専用フォルダを作成し、移動します。

### 証明書の作成

```bash
mkcert [固定IPアドレス]
```

以下のファイルが生成されます：

- [固定 IP アドレス].pem - サーバー証明書
- [固定 IP アドレス]-key.pem - 秘密鍵

### 完了

```bash
cd ..
```

元のフォルダに戻ります。

**重要な注意点**

- 証明書の有効期間は 27 か月です
- 秘密鍵は絶対に共有しないでください
- 証明書は安全な場所に保管してください

## local-ssl-proxy の設定

package.json の ssl:canisters, ssl:ii のエントリを、自分で設定した固定 IP アドレスに変更します。

### package.json への更新

```json
{
  "scripts": {
    "ssl:canisters": "local-ssl-proxy --key ./.mkcert/[静的IPアドレス]-key.pem --cert ./.mkcert/[静的IPアドレス].pem --source 14943 --target 4943",
    "ssl:ii": "local-ssl-proxy --key ./.mkcert/[静的IPアドレス]-key.pem --cert ./.mkcert/[静的IPアドレス].pem --source 24943 --target 4943"
  }
}
```

各設定の内容は下記のことをしています：

- `--key`：秘密鍵ファイルのパスを指定します
- `--cert`：サーバー証明書ファイルのパスを指定します
- `--source`：HTTPS でアクセスする際のポート番号です
- `--target`：実際の開発サーバーが動作しているポート番号です

**重要な注意点**

- [固定 IP アドレス]は、先ほど設定した固定 IP アドレスに置き換えてください
- サーバー証明書と秘密鍵のファイルパスは、mkcert で生成したファイルの場所と一致させてください

## ローカル replica の起動

ローカルで Canister を動かす実行環境のことをローカル replica と呼びます。
新しいターミナルを立ち上げて、以下のコマンドを実行します：

```bash
npm run dfx:start
```

ローカル replica が、4943 番ポートで起動します

### ローカル replica の停止方法

ローカル replica を停止するには、以下のいずれかの方法を使用します：

- 起動中のターミナルで Ctrl+C を押します
- 別のターミナルで`dfx stop`コマンドを実行します

**重要な注意点**
`Error: dfx is already running.`というエラーが出た場合は、すでに、dfx start を実行している可能性が高いです。一度、dfx stop でローカル replica を停止してから、再度、開発サーバを立ち上げてください。

## Canister のデプロイ for local

ローカル replica に、Canister をデプロイするには、以下のコマンドを実行します：

```bash
npm run dfx:deploy
```

このコマンドは下記のことをしています：

1. 全ての Canister（internet-identity, ii-integration, frontend, backend）をビルドします
2. ビルドした Canister をローカル replica にインストールします

**重要な注意点**

- デプロイ前に dfx:start が実行されている必要があります
- デプロイには数分かかる場合があります

## Canister のデプロイ for playground

playground に、Canister をデプロイするには、以下のコマンドを実行します：

```bash
npm run dfx:deploy:playgorund
```

このコマンドは下記のことをしています：

1. 全ての Canister（internet-identity, ii-integration, expo-starter-frontend, expo-starter-backend）をビルドします
2. ビルドした Canister を playground にインストールします

**重要な注意点**

- デプロイには数分かかる場合があります
- デプロイされた Canister は 20 分後に期限切れになります
- Playground デプロイメントには以下の制限があります：
  - メモリ使用量の上限は 1GB
  - サイクル転送命令は無視されます
  - Wasm ファイルを gzip 圧縮することはできません

## ICP メインネット(ic)へのデプロイ準備手順

1. 開発用の identity を作成して切り替えます

```bash
dfx identity new dev
dfx identity use dev
```

2. アカウント情報を確認します

```bash
dfx ledger account-id
dfx identity get-principal
```

3. デプロイに必要な準備をします

- 表示された Account ID に少量の ICP を送金します（5ICP くらいはあった方が無難）
- 送金後、以下のコマンドで Canister を作成します

```bash
dfx ledger --network ic create-canister $(dfx identity get-principal) --amount 4
```

4. Cycles ウォレットを設定します

```bash
dfx identity --ic deploy-wallet <作成されたCycles Wallet Canister ID>
dfx identity --network ic set-wallet <作成されたCycles Wallet Canister ID>
```

**重要な注意点**

- デプロイには以下が必要です：
  - ウォレット作成用の ICP
  - Canister デプロイ用の Cycles

## 開発者の秘密鍵のバックアップと復元

### 秘密鍵のエクスポート

```bash
dfx identity export dev > dev.pem
```

このコマンドは、dev アイデンティティの秘密鍵を PEM フォーマットで dev.pem ファイルに保存します。

### 秘密鍵のインポート

```bash
dfx identity import dev dev.pem
```

エクスポートした PEM ファイルから秘密鍵をインポートし、dev アイデンティティとして登録します。

**重要な注意点**

- インポート時にパスフレーズの入力を求められます
- パスフレーズは 8 文字以上である必要があります
- パスフレーズは忘れないように安全に保管してください
- PEM ファイルは秘密鍵を含むため、セキュアに保管する必要があります
- インポート完了後、不要な PEM ファイルは安全に削除することを推奨します

## Canister のデプロイ for ic

ic に、Canister をデプロイするには、以下のコマンドを実行します：

```bash
npm run dfx:deploy:ic
```

このコマンドは下記のことをしています：

1. 全ての Canister（internet-identity, ii-integration, expo-starter-frontend, expo-starter-backend）をビルドします
2. ビルドした Canister を ic にインストールします

**重要な注意点**

- デプロイには数分かかる場合があります
- メインネットへのデプロイには、運用のためのサイクル（実行手数料）が必要です

補足説明：

- サイクルは、Internet Computer 上で Canister を実行するために必要な計算リソースの支払い単位です
- メインネットでは、Canister の実行時間、メモリ使用量、ネットワーク通信量に応じてサイクルが消費されます
- サイクルは ICP トークンから変換して取得することができます

## local-ssl-proxy の起動

local-ssl-proxy の起動方法を説明します

### 起動コマンド

```bash
npm run ssl:canisters
npm run ssl:ii
npm run ssl:web
```

これらのコマンドは下記のことをしています：

1. ssl:canisters は Canister 用の HTTPS 接続を提供します（14943→4943）
2. ssl:ii は Internet Identity 用の HTTPS 接続を提供します（24943→4943）
3. ssl:web は Web アプリ用の HTTPS 接続を提供します（18081→8081）

**重要な注意点**

- 各コマンドは必ず別々の新しいターミナルで実行してください
- コマンドを実行する前に、対象のポートが使用されていないことを確認してください
- SSL 証明書のパスが正しく設定されていることを確認してください
- 起動後は Ctrl+C で個別に停止できます

## Expo 開発サーバーの起動

Expo 開発サーバーの起動方法を説明します

### 起動コマンド

```bash
npm run frontend:start
```

このコマンドを実行すると下記のことが行われます：

1. Expo の開発者サーバーが起動します
2. QR コードが表示されます
3. 操作用のメニューが表示されます

### 主な操作方法

- `w`キー：Web ブラウザでアプリを起動します

### スマートフォンでの実行方法

1. Expo Go アプリをインストールします
2. iOS の場合：カメラアプリで QR コードを読み取ります
3. Android の場合：Expo Go アプリで QR コードを読み取ります

**重要な注意点**

- PC とスマートフォンは同じ Wi-Fi に接続してください
- Expo 開発サーバーの停止は Ctrl+C で行います

**Android の制限事項**

- Android では、ローカルの Internet Identity は動作しません
- メインネットの Internet Identity は動作します
- Expo Go でのテストは、iOS で行ってください

## Internet Identity の注意点

Choose Identity で Identity を選んだときに、Unknown Internet Identity のエラーが出る場合があります。
これは、Identity を作成後に、ローカル Internet Identity を再デプロイしたときに起こります。
ブラウザは、Identity を覚えていますが、ローカル Internet Identity は Identity を忘れてしまっているためです。
![Unknown Internet Identity](./images/unknown-internet-identity.png)

このような場合は、Identity の下に表示されている More options をタップしてください。左下の Create New ボタンをタップしましょう。10000 の Identity を再作成できます。
![Create new Identity](./images/create-new.png)
