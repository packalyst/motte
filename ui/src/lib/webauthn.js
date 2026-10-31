// Passkey (WebAuthn) client helpers. The backend speaks standard WebAuthn JSON: binary fields
// (challenge, ids, signatures) are base64url strings, which the browser's credential API needs as
// ArrayBuffers — these helpers convert both ways. Same-origin fetch with credentials passes the
// panel's Origin-based CSRF check, so no token plumbing is needed.

function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  const pad = s.length % 4
  if (pad) s += '='.repeat(4 - pad)
  const bin = atob(s)
  const buf = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i)
  return buf.buffer
}

function bufToB64url(buf) {
  const bytes = new Uint8Array(buf)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function post(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.error || data.message || 'Request failed')
  return data
}

// supported reports whether this context can do WebAuthn at all (needs a secure context).
export function passkeysSupported() {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials
}

// passkeyRegister adds a new passkey for the logged-in user, labelled `name`. Registration is
// step-up-gated server-side (password only), so `proof` (stepUpConfirm's) must be supplied.
export async function passkeyRegister(name, proof = {}) {
  if (!passkeysSupported()) throw new Error('This browser or connection does not support passkeys (needs HTTPS).')
  const opts = await post('/api/auth/passkeys/register/begin', proof)
  const pk = opts.publicKey
  pk.challenge = b64urlToBuf(pk.challenge)
  pk.user.id = b64urlToBuf(pk.user.id)
  if (pk.excludeCredentials) {
    pk.excludeCredentials = pk.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }))
  }
  const cred = await navigator.credentials.create({ publicKey: pk })
  if (!cred) throw new Error('No passkey was created')
  const body = {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufToB64url(cred.response.attestationObject),
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      transports: cred.response.getTransports ? cred.response.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  }
  return post('/api/auth/passkeys/register/finish?name=' + encodeURIComponent(name || 'Passkey'), body)
}

// assert asks the browser to answer a passkey challenge (the server's publicKey options) and
// returns the answer as the JSON the server verifies.
async function assert(pk) {
  pk.challenge = b64urlToBuf(pk.challenge)
  if (pk.allowCredentials) {
    pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }))
  }
  const assertion = await navigator.credentials.get({ publicKey: pk })
  if (!assertion) throw new Error('No passkey was used')
  return {
    id: assertion.id,
    rawId: bufToB64url(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufToB64url(assertion.response.authenticatorData),
      clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
      signature: bufToB64url(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : null,
    },
    clientExtensionResults: assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {},
  }
}

// passkeyLogin performs a passwordless (discoverable) login and returns the login response.
export async function passkeyLogin() {
  if (!passkeysSupported()) throw new Error('This browser or connection does not support passkeys (needs HTTPS).')
  const data = await post('/api/auth/passkeys/login/begin')
  const body = await assert(data.publicKey)
  return post('/api/auth/passkeys/login/finish?challengeId=' + encodeURIComponent(data.challengeId), body)
}

// passkeyStepUp confirms one sensitive request ({ method, url }, exactly as it will be sent) with a
// passkey instead of the password: the answer only works for that request, from this session,
// once. Send it in the request body as { passkey: answer }.
export async function passkeyStepUp(action) {
  if (!passkeysSupported()) throw new Error('This browser or connection does not support passkeys (needs HTTPS).')
  const data = await post('/api/auth/stepup/passkey', action)
  return assert(data.publicKey)
}
