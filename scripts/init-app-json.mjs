import { readFile, writeFile, readdir } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
console.log('Root directory:', rootDir);
const appName = path.basename(rootDir).toLowerCase();
console.log('App name:', appName);
const packageName = `com.example.${appName.replace(/[.-]/g, '')}`;
console.log('Package name:', packageName);
const frontendPath = path.join(rootDir, 'src', 'frontend');
const appJsonPath = path.join(frontendPath, 'app.json');

const readAndParseJsonFile = async (filePath) => {
  if (!existsSync(filePath)) {
    return undefined;
  }

  const data = await readFile(filePath, 'utf8');

  return JSON.parse(data);
};

const initAppJson = async () => {
  const appJson = await readAndParseJsonFile(appJsonPath);

  if (!appJson) {
    return;
  }

  if (appJson?.expo?.extra?.eas) {
    delete appJson.expo.extra.eas;
  }

  if (appJson?.expo?.owner) {
    delete appJson.expo.owner;
  }

  appJson.expo.name = appName;
  appJson.expo.slug = appName;
  appJson.expo.scheme = appName;

  if (appJson?.expo?.android?.package) {
    appJson.expo.android.package = packageName;
  }

  if (appJson?.expo?.ios?.bundleIdentifier) {
    appJson.expo.ios.bundleIdentifier = packageName;
  }

  console.log('Updated app.json:', JSON.stringify(appJson, undefined, 2));

  await writeFile(appJsonPath, JSON.stringify(appJson, undefined, 2));
};

const main = async () => {
  try {
    await initAppJson();
  } catch (error) {
    console.log('Error:', error);
    process.exit(1);
  }
};

main();
