import { readFile, writeFile, readdir } from 'fs/promises';
import { existsSync, readdirSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { spawn, exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
console.log('Root directory:', rootDir);

const mkcertPath = path.join(rootDir, '.mkcert');
const frontendPath = path.join(rootDir, 'src', 'frontend');
const appJsonPath = path.join(frontendPath, 'app.json');

const dfxNetwork = process.env.DFX_NETWORK;
if (!dfxNetwork) {
  throw new Error('DFX_NETWORK is not set');
}
console.log('DFX Network:', dfxNetwork);

const getCanisterIdsPath = () => {
  switch (dfxNetwork) {
    case 'local':
      return path.join(rootDir, '.dfx', 'local', 'canister_ids.json');
    case 'playground':
      return path.join(rootDir, '.dfx', 'playground', 'canister_ids.json');
    case 'ic':
      return path.join(rootDir, 'canister_ids.json');
    default:
      throw new Error(`Unsupported network: ${dfxNetwork}`);
  }
};

const readAndParseJsonFile = async (filePath) => {
  if (!existsSync(filePath)) {
    return undefined;
  }

  const data = await readFile(filePath, 'utf8');

  return JSON.parse(data);
};

const normarizeCanisterIds = (canisterIds) => {
  const normalized = {};

  Object.entries(canisterIds).forEach(([key, value]) => {
    if (!key.startsWith('_')) {
      normalized[key] = Object.values(value)[0];
    }
  });

  return normalized;
};

const spawnProcess = (command, args) => {
  return new Promise((resolve, reject) => {
    const process = spawn(command, args);
    let stdout = '';
    let stderr = '';

    process.stdout.on('data', (data) => {
      stdout += data.toString();
      console.log(data.toString());
    });

    process.stderr.on('data', (data) => {
      stderr += data.toString();
      console.error(data.toString());
    });

    process.on('close', (status) => {
      if (status === 0) {
        resolve(status);
      } else {
        reject(
          new Error(
            `Command failed with status ${status}\nStdout: ${stdout}\nStderr: ${stderr}`,
          ),
        );
      }
    });

    process.on('error', (error) => {
      reject(error);
    });
  });
};

const createCanisters = async () => {
  try {
    const status = await spawnProcess('dfx', [
      'canister',
      'create',
      '--all',
      '--network',
      dfxNetwork,
    ]);

    if (status !== 0) {
      console.error('Failed to create canisters status:', status);
    }

    return status === 0;
  } catch (error) {
    console.error('Error creating canisters:', error);
    return false;
  }
};

const getLocalIPAddress = async () => {
  if (!existsSync(mkcertPath)) {
    throw new Error(
      'Mkcert path does not exist. See https://github.com/higayasuo/expo-icp/blob/main/docs/setup.md#mkcert-installation https://github.com/higayasuo/expo-icp/blob/main/docs/setup.md#setting-up-static-ip-address and https://github.com/higayasuo/expo-icp/blob/main/docs/setup.md#creating-server-certificate',
    );
  }

  const files = await readdir(mkcertPath);
  const pemFile = files.find((file) => file.endsWith('-key.pem'));

  if (!pemFile) {
    throw new Error(
      'No pem file found in mkcert path. See https://github.com/higayasuo/expo-icp/blob/main/docs/setup.md#mkcert-installation https://github.com/higayasuo/expo-icp/blob/main/docs/setup.md#setting-up-static-ip-address and https://github.com/higayasuo/expo-icp/blob/main/docs/setup.md#creating-server-certificate',
    );
  }

  return path.basename(pemFile, '-key.pem');
};

const getExpoScheme = async () => {
  const { stdout } = await execAsync(
    `npx expo config "${frontendPath}" --json`,
  );
  const json = JSON.parse(stdout);
  //console.log('Expo config json:', json);
  return json.scheme ?? '';
};

const getEnvFilePath = (dir) => {
  if (!existsSync(path.join(dir, 'package.json'))) {
    return undefined;
  }

  if (existsSync(path.join(dir, 'Cargo.toml'))) {
    return undefined;
  }

  const constantsPath = path.join(dir, 'constants');

  if (existsSync(constantsPath)) {
    return path.join(constantsPath, 'env.generated.ts');
  }

  const srcPath = path.join(dir, 'src');

  if (existsSync(srcPath)) {
    return path.join(srcPath, 'env.generated.ts');
  }

  return undefined;
};

const getEnvFilePaths = async () => {
  const srcDir = path.join(rootDir, 'src');
  const results = [];
  const list = readdirSync(srcDir, { withFileTypes: true });
  for (const dirent of list) {
    if (dirent.isDirectory()) {
      const subDir = path.join(srcDir, dirent.name);
      const envFilePath = getEnvFilePath(subDir);
      if (envFilePath) {
        results.push(envFilePath);
      }
    }
  }
  return results;
};

const generateEnvFiles = async (
  normalizedCanisterIds,
  localIPAddress,
  expoScheme,
) => {
  const canisterIdConstants = Object.entries(normalizedCanisterIds)
    .map(
      ([key, value]) =>
        `export const CANISTER_ID_${key
          .replace(/-/g, '_')
          .toUpperCase()} = '${value}';`,
    )
    .join('\n');

  const content = `// This file is auto-generated. Do not edit this file.
// Generated from scripts/setup-env.js

export const LOCAL_IP_ADDRESS = '${localIPAddress}';
export const DFX_NETWORK = '${dfxNetwork}';
export const CANISTER_ID_INTERNET_IDENTITY = 'rdmx6-jaaaa-aaaaa-aaadq-cai';
${canisterIdConstants}
export const EXPO_SCHEME = '${expoScheme}';
`;
  console.log('Env file content:', content);

  const envFilePaths = await getEnvFilePaths();
  envFilePaths.forEach(async (envFilePath) => {
    await writeFile(envFilePath, content);
  });
};

const updateAppJson = async (frontendCanisterId) => {
  const appJson = await readAndParseJsonFile(appJsonPath);
  console.log('app.json:', JSON.stringify(appJson, undefined, 2));
  const host = `${frontendCanisterId}.icp0.io`;
  const appLinks = [`applinks:${host}`];

  if (!appJson) {
    throw new Error(
      `src/frontend/app.json does not exist. You need to manually update the expo.android.intentFilters.data.host in app.json to ${host}.`,
    );
  }

  if (!appJson?.expo?.android?.intentFilters?.[0]?.data?.[0]?.host) {
    throw new Error(
      `src/frontend/app.json does not have expo.android.intentFilters.data.host. You need to manually update the expo.android.intentFilters.data.host in app.json to ${host}.`,
    );
  }

  if (!appJson?.expo?.ios) {
    throw new Error(
      `src/frontend/app.json does not have expo.ios. You need to manually update the expo.ios.associatedDomains in app.json to ${JSON.stringify(
        appLinks,
        undefined,
        2,
      )}.`,
    );
  }

  appJson.expo.android.intentFilters[0].data[0].host = host;
  appJson.expo.ios.associatedDomains = appLinks;
  console.log('Updated app.json:', JSON.stringify(appJson, undefined, 2));

  await writeFile(appJsonPath, JSON.stringify(appJson, undefined, 2));
};

const setupCanisterIds = async () => {
  const canisterIdsPath = getCanisterIdsPath();
  console.log('Canister IDs path:', canisterIdsPath);

  const canisterIds = await readAndParseJsonFile(canisterIdsPath);
  console.log('Canister IDs:', canisterIds);

  if (
    canisterIds &&
    canisterIds['ii-integration'] &&
    canisterIds.frontend &&
    canisterIds.backend
  ) {
    return normarizeCanisterIds(canisterIds);
  }

  const created = await createCanisters();

  if (!created) {
    process.exit(1);
  }

  const canisterIds2 = await readAndParseJsonFile(canisterIdsPath);
  console.log('2nd Canister IDs:', canisterIds2);

  return normarizeCanisterIds(canisterIds2);
};

const main = async () => {
  try {
    const normalizedCanisterIds = await setupCanisterIds();
    console.log('Normalized Canister Ids:', normalizedCanisterIds);

    const localIPAddress = await getLocalIPAddress();
    console.log('Local IP Address:', localIPAddress);

    const expoScheme = await getExpoScheme();
    console.log('Expo Scheme:', expoScheme);

    await generateEnvFiles(normalizedCanisterIds, localIPAddress, expoScheme);

    if (dfxNetwork === 'ic') {
      await updateAppJson(normalizedCanisterIds.frontend);
    }
  } catch (error) {
    console.log('Error:', error);
    process.exit(1);
  }
};

main();
