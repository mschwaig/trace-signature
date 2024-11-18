import * as jose from 'https://deno.land/x/jose@v5.9.6/index.ts'
import { encodeBase64 } from "https://deno.land/x/jose@v5.9.6/runtime/base64url.ts";
import { JSONPath } from 'npm:jsonpath-plus@10.2.0'

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
  var detached: string[] = []
  toDetach.forEach(async path => {
    const matches = JSONPath({ path, json: traceData });
    const content = new TextEncoder().encode(JSON.stringify(matches));
    detached.push(encodeBase64(content));
    
    const hash = await crypto.subtle.digest("SHA-256", content);
    traceData = JSONPath({
      path,
      json: traceData,
      callback: () => "~" + encodeBase64(new Uint8Array(hash)),
      resultType: 'all'
    });
  });
  return { traceData, detached };
 }

// Learn more at https://docs.deno.com/runtime/manual/examples/module_metadata#concepts
if (import.meta.main) {
  // generating key
  const { publicKey, privateKey } = await jose.generateKeyPair('EdDSA', { crv: 'Ed25519' });
  console.log("key:", publicKey);
  // detaching
  const attached = JSON.parse("{\"key\": \"asdf\" }");
  console.log("attached:", attached);
  const detached = await detach(attached, ["key"]);
  console.log("detached:", detached);
  // signing
  console.log("signed trace:", await signJws(detached.traceData, privateKey));

  // verifying

  // attaching
}
