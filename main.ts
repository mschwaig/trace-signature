import * as jose from 'https://deno.land/x/jose@v5.9.6/index.ts'
import { encodeBase64 } from "https://deno.land/x/jose@v5.9.6/runtime/base64url.ts";

export async function signJws(traceData: JSON, privateKey: jose.KeyLike): Promise<string> {
  const traceSignature = await new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify(traceData))
  ).setProtectedHeader(
    {
      alg: "EdDSA",
      type: "ntrace",
      v: "1"
    }
  ).sign(
    privateKey
  );
  return traceSignature;
}

interface DetachResult {
  traceData: any;
  detached: string[];
 }
 
 export async function detach(traceData: JSON, toDetach: string[]): Promise<DetachResult> {
  var detached: string[] = [];

  for (const attr of toDetach) {
    const value = traceData[attr];
    const content = new TextEncoder().encode(JSON.stringify(value));
    detached.push("~" + encodeBase64(content));
    const hash = await crypto.subtle.digest("SHA-256", content);
    traceData[attr] = "~" + encodeBase64(new Uint8Array(hash));
  }
  
  return { traceData, detached };
}

// Learn more at https://docs.deno.com/runtime/manual/examples/module_metadata#concepts
if (import.meta.main) {
  // generating key
  const { publicKey, privateKey } = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519' });
  console.log("key:", publicKey);
  // detaching
  const attached = JSON.parse("{\"key\": \"asdyvyasdfasfsafasdfasfasfasfdasfafsafsafasdfsafasfsafasdfasfsdfasdfasfsadfsadfasfdsdfasfdafvcsasfdsafasasdfsf\" }");
  console.log("attached:", attached);
  const detached = await detach(attached, ["key"]);
  console.log("detached:", detached);
  // signing
  console.log("signed trace:", await signJws(detached.traceData, privateKey));
  for (const attr of detached.detached) {
    console.log(attr)
  }

  // verifying

  // attaching
}
