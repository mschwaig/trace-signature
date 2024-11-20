import * as jose from 'https://deno.land/x/jose@v5.9.6/index.ts'
import { encodeBase64 } from "https://deno.land/x/jose@v5.9.6/runtime/base64url.ts";

/* illustrative example 

base64({ type: "", v="2", alg="EdDSA", crv="Ed25519", detach="SHA-256" }).
base64({
    in:
    buildLog: "~{base64(hash(logContent))}",
    builder = {
        rebuild = "1",
        key = "nixpkgs:growing-jennet:${key(nixpkgs:growing-jennet)}",
        flakeUrl: asfasf.attr
        keyAtt: "~{base64(hash(keyAttestation)))}",
    }
    stats = "~{base64(hash(keyAttestation)))}",
    out:
}).
signature(everything_above)
~base64(
    keyAttestation
)
~base64(
    logContent
)
~base64(
    hash(runtime stats)
)
 */

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
  const attached = JSON.parse("{\"key\": \"asdf\" }"); // https://gchq.github.io/CyberChef/#recipe=SHA2('256',64,160)From_Hex('Auto')To_Base64('A-Za-z0-9%2B/%3D')&input=ImFzZGYi
  console.log("attached:", attached);
  const detached = await detach(attached, ["key"]); // https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9%2B/%3D')&input=ImFzZGYi
  console.log("detached:", detached);
  // signing

  const signed = await signJws(detached.traceData, privateKey);
  console.log("signed trace:", signed);
  console.log("detachable elements:");
  for (const attr of detached.detached) {
    console.log(attr)
  }

  // verifying

  // attaching
}
