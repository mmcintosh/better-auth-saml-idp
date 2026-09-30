// A deliberately small sign-in page. After success it follows `callbackURL` only if it points
// back to this origin (the SAML plugin passes its absolute /saml2/idp/resume URL).
export function signInPage(url: string): Response {
  void url;
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style nonce="${nonce}">body{font:16px system-ui;max-width:24rem;margin:3rem auto;padding:0 1rem}
label{display:block;margin:.75rem 0 .25rem}input{width:100%;padding:.5rem;box-sizing:border-box}
button{margin-top:1rem;padding:.5rem 1rem}#err{color:#b00020}</style></head><body>
<h1>Sign in</h1>
<form id="f"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" minlength="8" required>
<label id="nameLabel" for="name" hidden>Name</label><input id="name" name="name" hidden>
<button id="submit" type="submit">Sign in</button> <button id="toggle" type="button">Create an account instead</button>
<p id="err" role="alert"></p></form>
<p id="sent" hidden>Check your email for a verification link to finish signing in.</p>
<script nonce="${nonce}">
const f=document.getElementById("f"),err=document.getElementById("err"),name=document.getElementById("name"),nameLabel=document.getElementById("nameLabel");
let signUp=false;
document.getElementById("toggle").onclick=()=>{signUp=!signUp;name.hidden=nameLabel.hidden=!signUp;name.required=signUp;
  document.getElementById("submit").textContent=signUp?"Create account":"Sign in";
  document.getElementById("toggle").textContent=signUp?"I already have an account":"Create an account instead";};
function safeCallback(){const raw=new URLSearchParams(location.search).get("callbackURL")||"/";
  try{const u=new URL(raw,location.origin);return u.origin===location.origin?u.href:"/";}catch{return "/";}}
f.onsubmit=async(e)=>{e.preventDefault();err.textContent="";
  const body={email:f.email.value,password:f.password.value,callbackURL:safeCallback()};if(signUp)body.name=f.name.value||f.email.value;
  const r=await fetch("/api/auth/"+(signUp?"sign-up":"sign-in")+"/email",{method:"POST",headers:{"content-type":"application/json"},credentials:"include",body:JSON.stringify(body)});
  if(r.ok&&signUp){f.hidden=true;document.getElementById("sent").hidden=false;return;}
  if(r.ok){location.assign(safeCallback());return;}
  const j=await r.json().catch(()=>({}));err.textContent=j.message||("Failed ("+r.status+")");};
</script></body></html>`;
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
      "x-frame-options": "DENY",
      "cache-control": "no-store",
    },
  });
}
