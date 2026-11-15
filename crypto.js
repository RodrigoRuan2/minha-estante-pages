export const ITERATIONS=600000;
export const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
export function base64(buffer){let s='';const a=new Uint8Array(buffer);for(let i=0;i<a.length;i+=16384)s+=String.fromCharCode(...a.subarray(i,i+16384));return btoa(s);}
export async function derive(password,salt,iterations=ITERATIONS){const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
export async function seal(key,plain){const iv=crypto.getRandomValues(new Uint8Array(12));return {iv:base64(iv),ciphertext:base64(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(plain)))};}
export async function unseal(key,envelope){return new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(envelope.iv)},key,bytes(envelope.ciphertext)));}
