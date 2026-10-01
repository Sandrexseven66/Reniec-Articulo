const DB_NAME = 'reniec-demo-offline';
const STORE = 'records';

function openDb(): Promise<IDBDatabase> { return new Promise((resolve, reject) => { const request = indexedDB.open(DB_NAME, 1); request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: 'key' }); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); }); }
export async function putRecord(key: string, value: unknown) { const db = await openDb(); return new Promise<void>((resolve, reject) => { const tx = db.transaction(STORE, 'readwrite'); tx.objectStore(STORE).put({ key, value }); tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); }); }
export async function getRecord<T>(key: string): Promise<T | undefined> { const db = await openDb(); return new Promise((resolve, reject) => { const request = db.transaction(STORE).objectStore(STORE).get(key); request.onsuccess = () => resolve(request.result?.value); request.onerror = () => reject(request.error); }); }
export async function getAllRecords<T>(): Promise<T[]> { const db = await openDb(); return new Promise((resolve, reject) => { const request = db.transaction(STORE).objectStore(STORE).getAll(); request.onsuccess = () => resolve(request.result.map((row: {value: T}) => row.value)); request.onerror = () => reject(request.error); }); }
export function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
	if (value && typeof value === 'object') {
		return `{${Object.keys(value as Record<string, unknown>).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
	}
	return JSON.stringify(value);
}
export async function verifyOffline(envelope: any): Promise<{valid: boolean; signatureValid: boolean; hash: string}> { const payloadText = canonical(envelope.payload); const bytes = new TextEncoder().encode(payloadText); const digest = await crypto.subtle.digest('SHA-256', bytes); const hash = [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join(''); const binary = (text: string) => Uint8Array.from(atob(text), char => char.charCodeAt(0)); try { const key = await crypto.subtle.importKey('raw', binary(envelope.public_key), {name: 'Ed25519'}, false, ['verify']); const signatureValid = await crypto.subtle.verify({name: 'Ed25519'}, key, binary(envelope.signature), bytes); return {valid: signatureValid, signatureValid, hash}; } catch { return {valid: false, signatureValid: false, hash}; } }
