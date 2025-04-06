# 認証フロー

このドキュメントでは、Expo アプリでの Internet Identity 認証の詳細な認証フローについて説明します。

詳細な認証フローの図と説明については、[Internet Computer の公式ドキュメント](https://internetcomputer.org/docs/building-apps/security/iam#integrating-internet-identity-on-mobile-devices)を参照してください。

## 概要

認証フローは以下のステップで構成されています：

1. Expo アプリが SignIdentity（公開鍵・秘密鍵のペア）を生成し、セキュアに保存
2. Expo アプリが外部ブラウザで ii-integration を開く
3. ii-integration が中間セッションキーを生成
4. ii-integration が Internet Identity で認証を実行し、中間セッションキーを渡す
5. Internet Identity が ii-integration に DelegationIdentity を返す
6. ii-integration が中間セッションキーと DelegationIdentity から有効期限 15 分の DelegationChain を作成し、Expo アプリに返す
7. Expo アプリが SignIdentity と DelegationChain から DelegationIdentity を作成
8. Expo アプリが DelegationIdentity を使用してバックエンド canister と通信

## 詳細なフロー

### 1. Expo アプリが SignIdentity を生成

Expo アプリは SignIdentity（公開鍵・秘密鍵のペア）を生成します。SignIdentity はセキュアなストレージに保存され、アプリの再起動後も保持されます。

### 2. Expo アプリが ii-integration を開く

Expo アプリは外部ブラウザで ii-integration を開き、公開鍵と deep-link-type を渡します。これにより、ii-integration は Expo アプリの公開鍵を知ることができ、後で委譲チェーンを作成する際に使用します。

`deep-link-type`は、ii-integration が Expo アプリに戻る方法を指定するパラメータで、以下の 5 種類があります：

- **icp**: Internet Computer のフロントエンド canister を使用する場合
- **expo-go**: Expo Go アプリを使用する場合
- **dev-server**: 開発サーバーを使用する場合
- **modern**: Universal Links（iOS）または App Links（Android）を使用する場合
- **legacy**: カスタム URL スキームを使用する場合

### 3. ii-integration が中間セッションキーを生成

ii-integration は中間セッションキーを生成します。この中間セッションキーは、Internet Identity との認証プロセスで使用されます。

### 4. ii-integration が Internet Identity で認証

ii-integration は Internet Identity で認証を実行します。この際、中間セッションキーを使用します。

### 5. Internet Identity が DelegationIdentity を返す

Internet Identity は認証成功後に ii-integration に DelegationIdentity を返します。この DelegationIdentity は中間セッションキーに対して発行されます。

### 6. ii-integration が Expo アプリに DelegationChain を返す

ii-integration は有効期限 15 分の DelegationChain を作成し、Expo アプリに返します。この DelegationChain は、中間セッションキーと Expo アプリの公開鍵を使用して作成されます。

**重要**: DelegationChain の有効期限は 15 分に設定されています。この期限が切れると、ユーザーは再認証が必要になります。これはセキュリティ上の重要な考慮事項です。

#### 環境に応じた委譲チェーンの送信

ii-integration は実行環境に応じて、委譲チェーンを異なる方法で送信します：

1. **Web ブラウザの iframe の場合**：
   Web ブラウザの iframe 環境では、`window.parent.postMessage()` を使用して親ウィンドウ（Web アプリ）に委譲チェーンを送信します。これにより、Web アプリは委譲チェーンを受け取り、認証を完了できます。

2. **Expo アプリの場合**：
   Expo アプリ環境では、URI フラグメント（`#`以降の部分）を使用して委譲チェーンを送信します。これにより、委譲チェーンがサーバーに送信されることなく、Expo アプリに安全に転送されます。これは重要なセキュリティ上の考慮事項です：

3. **URI フラグメントの利点**: URI フラグメントは、ブラウザが URI を解決する際にサーバーに送信されません。URL パラメータやパスと異なり、委譲チェーンがプロキシアプリのバックエンド（IC の境界ノードやレプリカノード）に漏洩することを防ぎます。

4. **セキュリティ強化**: 悪意のある中間サーバーや境界ノードが委譲チェーンを傍受するリスクを軽減します。委譲チェーンはクライアントサイドでのみ処理され、サーバーには送信されません。

### 7. Expo アプリが DelegationIdentity を作成

Expo アプリは、1 で生成した SignIdentity と ii-integration から返された DelegationChain を使用して DelegationIdentity を作成します。

### 8. Expo アプリが DelegationIdentity を使用

Expo アプリは作成した DelegationIdentity を使用してバックエンド canister と通信します。この DelegationIdentity は、Internet Identity からの認証情報を含んでおり、バックエンド canister がユーザーを識別するために使用されます。

## セキュリティ上の考慮事項

認証フローには、以下のセキュリティ上の考慮事項が含まれています：

1. **秘密鍵の保護**:

   - **Native 環境**: SignIdentity の秘密鍵はセキュアなストレージに保存されます。
   - **Web 環境**: SignIdentity の秘密鍵は sessionStorage に保存されます。Native 環境ほどセキュアではありませんが、Content Security Policy (CSP) などの対策により、XSS などの攻撃に対する保護が行われています。

2. **中間セッションキー**: 中間セッションキーを使用して、セキュリティを強化します。このキーは WebCrypto API を使用して抽出不可能なキーとして作成され、短命であるべきです。

3. **DelegationChain の検証**: DelegationChain は使用前に、SignIdentity の public key と DelegationChain の public key が一致することを確認する必要があります。これにより、正しい委譲チェーンが使用されていることを保証します。

   **重要**: 使用するエージェントは、生成されたセッションキーが返された委譲チェーンに対応しているかを検証しない可能性があります。このようなエージェントを使用して署名付き更新呼び出しを行うと、提供された委譲チェーンを含むメッセージを作成し、不一致のキーで署名することになります。明らかに、IC は署名が委譲チェーンに対応していないため、このようなメッセージを拒否しますが、委譲チェーンは既に境界ノードやレプリカノードに漏洩しており、攻撃者が盗む可能性があります。そのため、委譲チェーンを使用する前に必ず検証する必要があります。

4. **オリジン検証**: ii-integration は postMessage を使用する場合、認証リクエストのオリジンを検証し、特定のフロントエンドオリジンに対してのみ委譲を発行します。これにより、委譲が意図しないオリジンに漏洩することを防ぎます。

5. **セッションタイムアウト**: DelegationChain は 15 分後に期限切れとなり、ユーザーは再認証が必要になります。

6. **URI フラグメントの使用**: 委譲チェーンは URI フラグメント（`#`以降の部分）を使用して送信され、サーバーに送信されないようにします。これにより、委譲チェーンがプロキシアプリのバックエンド（IC の境界ノードやレプリカノード）に漏洩することを防ぎます。

7. **アプリリンク/ユニバーサルリンクの使用**: 委譲チェーンは Android のアプリリンクや iOS のユニバーサルリンクを使用してモバイルアプリに返されます。これにより、ドメイン名/ホスト名がモバイルアプリにバインドされ、攻撃者が悪意のあるモバイルアプリを使用して委譲チェーンを受け取ることを防ぎます。
