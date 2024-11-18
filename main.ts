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
  var detached: string[] = [];
  
  for (const path of toDetach) {
    JSONPath({
      path,
      json: traceData,
      callback: async function (value, _, { parent, key }) {
        console.log(value)
        const content = new TextEncoder().encode(JSON.stringify(value));
        console.log(content)
        detached.push(encodeBase64(content));
        const hash = await crypto.subtle.digest("SHA-256", content);
        console.log(hash)
        parent[key] = "~" + encodeBase64(new Uint8Array(hash));
        console.log(parent)
        return parent;
      },
      //resultType: 'all'
    });
    //traceData[path] = v;
  }
  
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
  const detached = await detach(attached, ["$.key"]);
  console.log("detached:", detached);
  // signing
  console.log("signed trace:", await signJws(detached.traceData, privateKey));

  // verifying

  // attaching
}
