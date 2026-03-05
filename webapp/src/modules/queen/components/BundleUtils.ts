import type { OpaPolicy } from '../../../../tacplus/libs/opa/opa_pb.ts';

export interface BundleFile {
  path: string;
  content: string;
}

/**
 * Decode an OpaPolicy into a list of files.
 * If bundle (base64 tar.gz) is present, decode it.
 * If only source is present, wrap as a single file.
 */
export async function decodeBundleOrSource(policy: OpaPolicy): Promise<BundleFile[]> {
  if (policy.bundle) {
    return decodeTarGz(policy.bundle);
  }
  if (policy.source) {
    return [{ path: 'policy.rego', content: policy.source }];
  }
  return [];
}

/**
 * Encode a list of files into a tar.gz Blob for download.
 */
export async function encodeBundleToTgz(files: BundleFile[]): Promise<Blob> {
  const tarBytes = createTar(files);
  return gzipCompress(tarBytes);
}

// ---------------------------------------------------------------------------
// tar helpers (POSIX ustar, 512-byte blocks)
// ---------------------------------------------------------------------------

function createTar(files: BundleFile[]): Uint8Array {
  const blocks: Uint8Array[] = [];

  // Collect all unique directory prefixes so we emit dir headers
  const dirs = new Set<string>();
  for (const f of files) {
    const parts = f.path.split('/');
    for (let i = 1; i < parts.length; i++) {
      dirs.add(parts.slice(0, i).join('/') + '/');
    }
  }
  const sortedDirs = [...dirs].sort();
  for (const dir of sortedDirs) {
    blocks.push(makeTarHeader(dir, 0, true));
  }

  for (const file of files) {
    const data = new TextEncoder().encode(file.content);
    blocks.push(makeTarHeader(file.path, data.length, false));
    blocks.push(padTo512(data));
  }

  // Two empty 512-byte blocks mark end of archive
  blocks.push(new Uint8Array(1024));

  return concatBytes(blocks);
}

function makeTarHeader(name: string, size: number, isDir: boolean): Uint8Array {
  const header = new Uint8Array(512);
  writeString(header, 0, name, 100);                   // name
  writeOctal(header, 100, isDir ? 0o755 : 0o644, 8);   // mode
  writeOctal(header, 108, 0, 8);                        // uid
  writeOctal(header, 116, 0, 8);                        // gid
  writeOctal(header, 124, size, 12);                     // size
  writeOctal(header, 136, Math.floor(Date.now() / 1000), 12); // mtime
  // typeflag: '5' for dir, '0' for file
  header[156] = isDir ? 53 : 48;
  // magic "ustar\0" + version "00"
  writeString(header, 257, 'ustar', 6);
  header[263] = 0;
  writeString(header, 263, '00', 2);

  // Compute checksum: sum of all bytes in header, treating checksum field as spaces
  writeString(header, 148, '        ', 8);
  let cksum = 0;
  for (let i = 0; i < 512; i++) cksum += header[i];
  const cksumStr = cksum.toString(8).padStart(6, '0');
  writeString(header, 148, cksumStr, 7);
  header[155] = 0;

  return header;
}

function writeString(buf: Uint8Array, offset: number, str: string, len: number) {
  for (let i = 0; i < Math.min(str.length, len); i++) {
    buf[offset + i] = str.charCodeAt(i);
  }
}

function writeOctal(buf: Uint8Array, offset: number, val: number, len: number) {
  const str = val.toString(8).padStart(len - 1, '0');
  writeString(buf, offset, str, len - 1);
  buf[offset + len - 1] = 0;
}

function padTo512(data: Uint8Array): Uint8Array {
  const padded = Math.ceil(data.length / 512) * 512;
  if (padded === data.length) return data;
  const result = new Uint8Array(padded);
  result.set(data);
  return result;
}

function concatBytes(arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

// ---------------------------------------------------------------------------
// tar decode
// ---------------------------------------------------------------------------

function decodeTar(tarBytes: Uint8Array): BundleFile[] {
  const files: BundleFile[] = [];
  let offset = 0;
  const decoder = new TextDecoder();

  while (offset + 512 <= tarBytes.length) {
    const header = tarBytes.slice(offset, offset + 512);
    // End-of-archive: two empty blocks
    if (header.every((b) => b === 0)) break;

    const name = readString(header, 0, 100);
    const size = readOctal(header, 124, 12);
    const typeflag = header[156];

    offset += 512;

    // '0' or 0 (NUL) = regular file
    if (typeflag === 48 || typeflag === 0) {
      const content = decoder.decode(tarBytes.slice(offset, offset + size));
      files.push({ path: name, content });
    }

    // Advance past data blocks
    offset += Math.ceil(size / 512) * 512;
  }

  return files;
}

function readString(buf: Uint8Array, offset: number, len: number): string {
  let end = offset;
  while (end < offset + len && buf[end] !== 0) end++;
  return new TextDecoder().decode(buf.slice(offset, end));
}

function readOctal(buf: Uint8Array, offset: number, len: number): number {
  const str = readString(buf, offset, len).trim();
  return str ? parseInt(str, 8) : 0;
}

// ---------------------------------------------------------------------------
// gzip compress / decompress using Web Streams API
// ---------------------------------------------------------------------------

async function gzipCompress(data: Uint8Array): Promise<Blob> {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  void writer.write(new Uint8Array(data.buffer, data.byteOffset, data.byteLength) as unknown as BufferSource);
  void writer.close();
  return new Response(cs.readable).blob();
}

async function gzipDecompress(data: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream('gzip');
  const writer = ds.writable.getWriter();
  void writer.write(new Uint8Array(data.buffer, data.byteOffset, data.byteLength) as unknown as BufferSource);
  void writer.close();
  const buf = await new Response(ds.readable).arrayBuffer();
  return new Uint8Array(buf);
}

// ---------------------------------------------------------------------------
// base64 helpers
// ---------------------------------------------------------------------------

function base64ToBytes(b64: string): Uint8Array {
  const binStr = atob(b64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
  return bytes;
}

async function decodeTarGz(base64Bundle: string): Promise<BundleFile[]> {
  const compressed = base64ToBytes(base64Bundle);
  const tarBytes = await gzipDecompress(compressed);
  return decodeTar(tarBytes);
}
