import 'dotenv/config';
import { createCipheriv, randomBytes } from 'node:crypto';
import { access, mkdir, readFile, realpath, rename, stat, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

const [manifestPathArg, sourceRootArg, outputPathArg] = process.argv.slice(2);
if (!manifestPathArg || !sourceRootArg) {
  console.error('Usage: node scripts/import-private-files.mjs <manifest.json> <downloaded-files-directory> [output-map.json]');
  process.exit(2);
}

const manifestPath = path.resolve(manifestPathArg);
const sourceRoot = await realpath(path.resolve(sourceRootArg));
const outputPath = path.resolve(outputPathArg ?? './storage/migration/file-uri-map.json');
const storageRoot = path.resolve(process.env.PRIVATE_FILES_PATH || './storage/private');
const maxFileSize = 10 * 1024 * 1024;
const format = Buffer.from('Z8F1');
const encryptionKey = Buffer.from(String(process.env.PRIVATE_FILE_ENCRYPTION_KEY || '').trim(), 'base64');
if (encryptionKey.length !== 32) throw new Error('PRIVATE_FILE_ENCRYPTION_KEY must be a base64-encoded 32-byte key.');

const parsed = JSON.parse(await readFile(manifestPath, 'utf8'));
const files = Array.isArray(parsed) ? parsed : parsed.files;
if (!Array.isArray(files)) throw new Error('Manifest must be an array or an object with a files array.');
const seenUris = new Set();
const entries = [];

for (let index = 0; index < files.length; index++) {
  const entry = files[index];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new Error('Manifest item ' + (index + 1) + ' is not an object.');
  }
  const oldUri = String(entry.source_uri ?? entry.uri ?? '').trim();
  const relativeFile = String(entry.file ?? '').trim();
  if (!oldUri || oldUri.length > 2048 || !relativeFile || path.isAbsolute(relativeFile)) {
    throw new Error('Manifest item ' + (index + 1) + ' must have a source URI and a relative file path.');
  }
  if (seenUris.has(oldUri)) throw new Error('Manifest item ' + (index + 1) + ' duplicates a source URI.');
  seenUris.add(oldUri);
  const sourcePath = await realpath(path.resolve(sourceRoot, relativeFile));
  if (!sourcePath.startsWith(sourceRoot + path.sep)) {
    throw new Error('Manifest item ' + (index + 1) + ' points outside the downloaded-files directory.');
  }
  const metadata = await stat(sourcePath);
  if (!metadata.isFile() || metadata.size < 1 || metadata.size > maxFileSize) {
    throw new Error('Manifest item ' + (index + 1) + ' is empty, too large, or not a regular file.');
  }
  entries.push({ oldUri, sourcePath, relativeFile });
}

try {
  await access(outputPath);
  throw new Error('Output URI map already exists; choose a new output path to avoid overwriting it.');
} catch (error) {
  if (error?.code !== 'ENOENT') throw error;
}

const uriMap = Object.create(null);
const createdPaths = [];
const temporaryPaths = [];
try {
  for (const entry of entries) {
    const bytes = await readFile(entry.sourcePath);
    let extension;
    if (bytes[0] === 0xff && bytes[1] === 0xd8) extension = 'jpg';
    else if (bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) extension = 'png';
    else if (bytes.subarray(0, 5).toString('ascii') === '%PDF-') extension = 'pdf';
    else throw new Error('Downloaded item "' + path.basename(entry.relativeFile) + '" is not a JPG, PNG, or PDF.');

    const id = randomBytes(12).toString('hex');
    const baseName = path.basename(entry.relativeFile).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120).replace(/\.[^.]*$/, '');
    const name = (baseName || 'upload') + '.' + extension;
    const uri = 'mp/private/' + id + '/' + name;
    const target = path.resolve(storageRoot, id, name);
    if (!target.startsWith(storageRoot + path.sep)) throw new Error('Generated private-file path is invalid.');

    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
    const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
    const encrypted = Buffer.concat([format, iv, cipher.getAuthTag(), ciphertext]);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    const temporary = target + '.' + randomBytes(8).toString('hex') + '.tmp';
    temporaryPaths.push(temporary);
    await writeFile(temporary, encrypted, { flag: 'wx', mode: 0o600 });
    await rename(temporary, target);
    temporaryPaths.pop();
    createdPaths.push(target);
    uriMap[entry.oldUri] = uri;
  }

  await mkdir(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  const temporaryMap = outputPath + '.' + randomBytes(8).toString('hex') + '.tmp';
  temporaryPaths.push(temporaryMap);
  await writeFile(temporaryMap, JSON.stringify(uriMap, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await rename(temporaryMap, outputPath);
  temporaryPaths.pop();
  console.log('Encrypted ' + entries.length + ' private files and wrote the URI map to ' + path.relative(process.cwd(), outputPath) + '.');
  console.log('The map contains source and local file URIs only; no file contents or signatures are included.');
} catch (error) {
  await Promise.all([...createdPaths, ...temporaryPaths].map((filePath) => unlink(filePath).catch(() => undefined)));
  throw error;
}

