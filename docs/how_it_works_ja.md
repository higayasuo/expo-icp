# How it works
このドキュメントで、Expoアプリで、Internet Identityで認証し、ICPのBackendに接続する方法を学習します。

英語版は[こちら](how_it_works.md)です。

## Internet Identityとは

Internet Identityは、Internet Computer上のサービスを利用するためのアカウントシステムです。従来のGoogleアカウントやApple IDに相当するものです。

## ExpoでInternet Identityを使うときの工夫

### Internet IdentityはExpoで動作しない

- 動作しない理由:
  - Internet Identityは、window.postMessage()を使用する
  - Expoではwindow.postMessage()が未サポート

#### 解決方法

認証処理をWeb Frontendに分離し、以下のフローで実装します：

1. Expoアプリ側での処理:
  - SignIdentityを生成（公開鍵・秘密鍵のペア）
  - Web Frontendを外部ブラウザで起動
  - 生成した公開鍵をWeb Frontendに渡す

2. Web Frontend側での処理:
  - Expoアプリから受け取った公開鍵を使用
  - Internet Identity認証を実行
  - 認証成功後、DelegationChainを取得
  - DelegationChainをExpoアプリにリダイレクト(Native)/postMessage(Web)で返却

3. Expoアプリ側での認証完了処理:
  - SignIdentityとDelegationChainからDelegationIdentityを生成

### DelegationIdentityの保存

- 保存する要素:
  - SignIdentity:
    - Nativeの場合、セキュアなストレージ（expo-secure-store）に保存
    - Webの場合、sessionStorageに保存
  - DelegationChain:
    - Nativeの場合、通常のストレージ（@react-native-async-storage/async-storage）に保存
    - Webの場合、sessionStorageに保存

#### 再起動時のDelegationIdentity復元手順

1. ストレージからの読み込み:
  - SignIdentityとDelegationChainを読み込む

2. DelegationIdentityの生成:
  - 読み込んだSignIdentityとDelegationChainからDelegationIdentityを生成

## コードで理解しよう - Native(iOS/Android)編

今まで説明してきた内容をコードで理解しましょう。

### Expoアプリの起動時

#### baseKeyのセットアップ

baseKeyとは、アプリのSignIdentityです。

##### Reactのstate設定

```typescript
const [baseKey, setBaseKey] = useState<Ed25519KeyIdentity | undefined>(
  undefined,
);
```

##### 処理の流れ

1. セキュアなストレージからbaseKeyを読み込む:
```typescript
const storedBaseKey = await SecureStore.getItemAsync('baseKey');
```

2. baseKeyの初期化処理:
```typescript
if (storedBaseKey) {
  if (!baseKey) {
    console.log('Restoring baseKey');
    const key = Ed25519KeyIdentity.fromJSON(storedBaseKey);
    setBaseKey(key);
  }
} else {
  console.log('Generating new baseKey');
  const key = Ed25519KeyIdentity.generate();
  await SecureStore.setItemAsync('baseKey', JSON.stringify(key.toJSON()));
  setBaseKey(key);
}
```

##### 重要なポイント
- Ed25519KeyIdentityはSignIdentityの一種
- セキュアなストレージを使用する理由は秘密鍵の保護のため
- 既存のbaseKeyがある場合は復元、ない場合は新規生成

#### identityのセットアップ

identityとは、DelegationIdentityのことです。

##### Reactのstate設定
```typescript
const [identity, setIdentity] = useState<DelegationIdentity | undefined>(
  undefined,
);
```

##### 処理の流れ

1. 通常ストレージからdelegationを読み込む:
```typescript
const storedDelegation = await AsyncStorage.getItem('delegation');
```

2. identityの復元処理:
```typescript
if (!identity && storedBaseKey && storedDelegation) {
  const baseKey = Ed25519KeyIdentity.fromJSON(storedBaseKey);
  const delegation = DelegationChain.fromJSON(storedDelegation);
  const identity = DelegationIdentity.fromDelegation(baseKey, delegation);

  if (isDelegationValid(delegation)) {
    console.log('Setting identity from baseKey and delegation');
    setIdentity(identity);
  } else {
    console.log('Invalid delegation chain, removing delegation');
    await AsyncStorage.removeItem('delegation');
  }
}
```

##### 重要なポイント
- identityが既に存在する場合は処理をスキップ
- delegationの有効期限は8時間（デフォルト）
- 有効期限切れのdelegationは削除される

##### セットアップ完了の管理
```typescript
const [isReady, setIsReady] = useState(false);
setIsReady(true);  // セットアップ完了時に更新
```

[useAuth.tsのソースコード](../src/expo-starter-frontend/hooks/useAuth.ts)

### Expoアプリでのログイン処理

#### 概要
- 目的：Internet Identity認証のためのWeb Frontend（ii-integration）を呼び出す
- 処理の流れ：
  1. 認証に必要なURLとパラメータの準備
  2. 外部ブラウザでii-integrationを起動
  3. 認証後にログイン時のページに戻るための設定

#### コードの全体像
```typescript
const redirectUri = createURL('/');

if (!baseKey) {
  throw new Error('No base key');
}

const pubkey = toHex(baseKey.getPublicKey().toDer());

const iiUri = getInternetIdentityURL();

const iiIntegrationURL = getCanisterURL(
  ENV_VARS.CANISTER_ID_II_INTEGRATION,
);
const url = new URL(iiIntegrationURL);

url.searchParams.set('redirect_uri', redirectUri);
url.searchParams.set('pubkey', pubkey);
url.searchParams.set('ii_uri', iiUri);

await AsyncStorage.setItem('lastPath', pathname);
await WebBrowser.openBrowserAsync(url.toString());
```

#### 各処理の詳細説明

1. リダイレクトURLの設定
```typescript
import { createURL } from 'expo-linking';
const redirectUri = createURL('/');
```
- 認証後にアプリに戻るためのカスタムURL
- createURLは開発環境と本番環境の違いを吸収
- Expo Goでの開発時は、特殊なカスタムURLになっている

2. 公開鍵の準備
```typescript
if (!baseKey) {
  throw new Error('No base key');
}
const pubkey = toHex(baseKey.getPublicKey().toDer());
```
- baseKey（アプリのSignIdentity）から公開鍵を取得
- 16進数文字列に変換して使用

3. Internet IdentityのURL設定
```typescript
const iiUri = getInternetIdentityURL();
```
- 環境に応じたInternet IdentityのURLを取得
- 本番環境：`https://identity.ic0.app`
- 開発環境：ローカルCanisterのURL
  - Chrome：`http://<canisterId>.localhost:4943`
  - その他：`https://<HOSTのIPアドレス>:24943/?canisterId=<canisterId>`

4. ii-integrationのURL生成
```typescript
const iiIntegrationURL = getCanisterURL(
  ENV_VARS.CANISTER_ID_II_INTEGRATION,
);
const url = new URL(iiIntegrationURL);

url.searchParams.set('redirect_uri', redirectUri);
url.searchParams.set('pubkey', pubkey);
url.searchParams.set('ii_uri', iiUri);
```
- ii-integration用のベースURL生成
- 必要なパラメータの設定
  - redirect_uri：認証後の戻り先URL
  - pubkey：アプリの公開鍵
  - ii_uri：Internet IdentityのURL

5. ブラウザ起動前の準備と実行
```typescript
await AsyncStorage.setItem('lastPath', pathname);
await WebBrowser.openBrowserAsync(url.toString());
```
- 現在のページパスを保存（認証後の画面遷移用）
- 外部ブラウザでii-integrationを起動

#### 開発環境での注意点

##### ローカル開発用サーバーへのアクセス方法

1. PCからのアクセス:
  - localhost（127.0.0.1）でアクセス可能
  - Chrome: `http://<canisterId>.localhost:4943`で直接アクセス可能
  - Chrome以外: `http://localhost:4943/?canisterId=<canisterId>`で直接アクセス可能

2. スマートフォンからのアクセス:
  - localhostは使用できない
  - PCのIPアドレスを使用する必要がある（例：192.168.0.210）
  - セキュリティ要件によりhttpsでのアクセスが必要

##### HTTPSアクセスの設定

1. local-ssl-proxyの設定:
```json
"ssl:ii": "local-ssl-proxy --source 24943 --target 4943 --key ./.mkcert/192.168.0.210-key.pem --cert ./.mkcert/192.168.0.210.pem"
```

2. アクセス方法:
  - 元のアドレス: `http://localhost:4943`
  - プロキシ後: `https://192.168.0.210:24943`
  - スマートフォンからは後者のアドレスでアクセス

[useAuth.tsのソースコード](../src/expo-starter-frontend/hooks/useAuth.ts)

### ii-integrationの起動時の処理

#### 概要
- 目的：ログインボタンクリック時にInternet Identity認証を実行し、認証成功時にDelegationChainをExpoアプリに返却するイベントハンドラーを定義する
- 処理の流れ：
  1. URLパラメータから必要な情報を取得
  2. AuthClientを作成して認証を実行
  3. 認証成功後、DelegationChainをExpoアプリに返却

#### コードの全体像
```typescript
try {
  const { redirectUri, identity, iiUri } = parseParams();
  const authClient = await AuthClient.create({ identity });
  const loginButton = document.querySelector('#ii-login-button') as HTMLButtonElement;

  loginButton.addEventListener('click', async () => {
    renderError('');
    try {
      await authClient.login({
        identityProvider: iiUri,
        onSuccess: () => {
          try {
            const delegationIdentity = authClient.getIdentity() as DelegationIdentity;
            const url = buildRedirectURLWithDelegation(redirectUri, delegationIdentity);
            window.location.href = url;
          } catch (error) {
            renderError(formatError('delegation retrieval failed', error));
          }
        },
        onError: (error?: string) => {
          renderError(formatError('authentication rejected', error || 'Unknown error'));
        },
      });
    } catch (error) {
      renderError(formatError('login process failed', error));
    }
  });
} catch (error) {
  renderError(formatError('initialization failed', error));
}
```

#### 各処理の詳細説明

1. URLパラメータの取得と解析
```typescript
const { redirectUri, identity, iiUri } = parseParams();
```
- Expoアプリから受け取る情報：
  - redirectUri：認証後の戻り先URL
  - pubkey：Expoアプリの公開鍵
  - iiUri：Internet IdentityのURL
- 公開鍵のみを持つSignIdentityを生成

2. AuthClientの作成とログインボタンの取得
```typescript
const authClient = await AuthClient.create({ identity });
const loginButton = document.querySelector('#ii-login-button') as HTMLButtonElement;
```
- AuthClientの作成：
  - Expoアプリの公開鍵を含むidentityを使用
  - 署名権限の委譲に使用
- ログインボタンの取得：
  - このボタンのクリックで認証処理を開始するために使用

3. 認証処理の設定
```typescript
loginButton.addEventListener('click', async () => {
  renderError('');
  try {
    await authClient.login({
      identityProvider: iiUri,
      onSuccess: () => {
        try {
          const delegationIdentity = authClient.getIdentity() as DelegationIdentity;
          const url = buildRedirectURLWithDelegation(redirectUri, delegationIdentity);
          window.location.href = url;
        } catch (error) {
          renderError(formatError('delegation retrieval failed', error));
        }
      },
      onError: (error?: string) => {
        renderError(formatError('authentication rejected', error || 'Unknown error'));
      },
    });
  } catch (error) {
    renderError(formatError('login process failed', error));
  }
});
```
- ログインボタンクリック時の処理を設定
- クリックされたときの処理：
  - エラーメッセージをクリア
  - Internet Identity認証を実行
  - 認証成功時：DelegationChainを含むURLでExpoアプリに戻る
  - 認証失敗時：エラーメッセージを表示

4. DelegationChainの生成と返却
```typescript
const buildRedirectURLWithDelegation = (redirectUri: string, delegationIdentity: DelegationIdentity): string => {
  const delegationString = JSON.stringify(
    delegationIdentity.getDelegation().toJSON()
  );
  const encodedDelegation = encodeURIComponent(delegationString);
  return `${redirectUri}?delegation=${encodedDelegation}`;
};
```

- DelegationChainの取得と加工:
  - delegationIdentity.getDelegation()でDelegationChainを取得
  - DelegationChainには以下の情報が含まれる：
    - ユーザーの公開鍵
    - Expoアプリへの署名権限委譲の証明書
  - JSON文字列に変換してURLエンコード

- Expoアプリへの返却:
  - リダイレクトURLのクエリパラメータとしてDelegationChainを付加
  - 秘密鍵は含まれないため、URLでの受け渡しが可能
  - Expoアプリ側でSignIdentityと組み合わせてDelegationIdentityを生成

[ii-integrationのソースコード](../src/ii-integration/index.ts)

### ii-integrationからExpoアプリに戻ってきた時の処理

#### 概要
- 目的：認証後に受け取ったDelegationChainを使用してDelegationIdentityを生成する
  - DelegationIdentityにより、アプリがトランザクションに署名し、トランザクションの実行者はユーザーとして処理される
- 処理の流れ：
  1. URLからDelegationChainを取得
  2. DelegationIdentityを生成して保存
  3. 認証前の画面に戻る

#### コードの全体像
```typescript
useEffect(() => {
  if (identity || !baseKey || !url) {
    return;
  }

  const search = new URLSearchParams(url?.split('?')[1]);
  const delegation = search.get('delegation');

  if (delegation) {
    const chain = DelegationChain.fromJSON(JSON.parse(delegation));
    AsyncStorage.setItem('delegation', JSON.stringify(chain.toJSON()));
    const id = DelegationIdentity.fromDelegation(baseKey, chain);
    setIdentity(id);
    console.log('set identity from delegation');
    WebBrowser.dismissBrowser();
    restorePreLoginScreen();
  }
}, [url, baseKey]);
```

#### 各処理の詳細説明

1. 前提条件のチェック
```typescript
if (identity || !baseKey || !url) {
  return;
}
```
- 以下の場合は処理をスキップ：
  - すでにidentityが存在する
  - baseKeyが存在しない
  - URLが存在しない

2. DelegationChainの取得と処理
```typescript
const search = new URLSearchParams(url?.split('?')[1]);
const delegation = search.get('delegation');

if (delegation) {
  const chain = DelegationChain.fromJSON(JSON.parse(delegation));
  AsyncStorage.setItem('delegation', JSON.stringify(chain.toJSON()));
  const id = DelegationIdentity.fromDelegation(baseKey, chain);
  setIdentity(id);
}
```
- URLからDelegationChainを取得
- DelegationChainを保存
- baseKeyとDelegationChainからDelegationIdentityを生成

3. 画面遷移の処理
```typescript
const restorePreLoginScreen = async () => {
  const path = await AsyncStorage.getItem('lastPath');
  if (path) {
    navigate(path);
    await AsyncStorage.removeItem('lastPath');
  } else {
    router.replace('/');
  }
};
```
- 保存していた画面パスの取得と遷移：
  - lastPathが存在する場合：保存していた画面に遷移
  - lastPathが存在しない場合：ルート画面に遷移
- 使用済みのlastPathは削除

#### 重要なポイント
- DelegationChainとbaseKeyの組み合わせにより：
  - アプリがトランザクションに署名可能
  - トランザクションはユーザーの操作として処理される
- DelegationChainはセキュアな情報を含まないため通常のストレージに保存

[useAuth.tsのソースコード](../src/expo-starter-frontend/hooks/useAuth.ts)

### バックエンドへのアクセス方法

#### 概要
- 目的：Actorを使用してバックエンドと型安全に通信する
- 特徴：
  - Rustで実装されたバックエンドにTypeScriptからアクセス
  - DelegationIdentityを使用してトランザクションに署名

#### フロントエンド側の実装
```typescript
// Actorの生成
const { identity, ... } = useAuth();
const backend = identity ? createBackend(identity) : undefined;

// バックエンドの呼び出し
return backend.whoami();
```

#### バックエンド側の実装（Rust）
```rust
#[ic_cdk::query]
fn whoami() -> String {
    ic_cdk::caller().to_text()
}
```

#### 処理の流れ
- フロントエンド：
  - DelegationIdentityを使用してActorを作成
  - Actorを通じてバックエンドのメソッドを呼び出し
- バックエンド：
  - 呼び出し元（ユーザー）のPrincipalを文字列として返却

[expo-starter-backendのソースコード](../src/expo-starter-backend/src/lib.rs)



