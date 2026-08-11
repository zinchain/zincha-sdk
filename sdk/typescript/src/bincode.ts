import type { BigNumberish } from "./types.ts";

export function asU64(value: BigNumberish, field = "value"): bigint {
  const parsed = typeof value === "bigint" ? value : BigInt(value);
  if (parsed < 0n || parsed > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`${field} must fit in unsigned 64 bits`);
  }
  return parsed;
}

export function asU32(value: number, field = "value"): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error(`${field} must fit in unsigned 32 bits`);
  }
  return value;
}

export function asU16(value: number, field = "value"): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error(`${field} must fit in unsigned 16 bits`);
  }
  return value;
}

export class BincodeWriter {
  private readonly chunks: Uint8Array[] = [];

  writeU8(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) {
      throw new Error("value must fit in unsigned 8 bits");
    }
    this.chunks.push(new Uint8Array([value]));
  }

  writeU16(value: number): void {
    const out = new Uint8Array(2);
    new DataView(out.buffer).setUint16(0, asU16(value), true);
    this.chunks.push(out);
  }

  writeU32(value: number): void {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, asU32(value), true);
    this.chunks.push(out);
  }

  writeU64(value: BigNumberish): void {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, asU64(value), true);
    this.chunks.push(out);
  }

  writeF32(value: number): void {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setFloat32(0, value, true);
    this.chunks.push(out);
  }

  writeF64(value: number): void {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setFloat64(0, value, true);
    this.chunks.push(out);
  }

  writeString(value: string): void {
    this.writeBytes(new TextEncoder().encode(value));
  }

  writeBytes(value: Uint8Array): void {
    this.writeU64(value.length);
    this.chunks.push(value);
  }

  writeRaw(value: Uint8Array): void {
    this.chunks.push(value);
  }

  /** bincode Option<T>: 0u8 (None) or 1u8 + T (Some). */
  writeOption<T>(value: T | null | undefined, encode: (writer: BincodeWriter, value: T) => void): void {
    if (value === null || value === undefined) {
      this.writeU8(0);
    } else {
      this.writeU8(1);
      encode(this, value);
    }
  }

  /** bincode Vec<T>: u64 length + each element. */
  writeVec<T>(values: readonly T[], encode: (writer: BincodeWriter, value: T) => void): void {
    this.writeU64(values.length);
    for (const value of values) {
      encode(this, value);
    }
  }

  finish(): Uint8Array {
    const total = this.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}
