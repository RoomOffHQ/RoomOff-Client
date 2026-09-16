const RoomOffSecurity = (() => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const iterations = 600000;
  let roomKey = null;
  let localKeyPair = null;
  let localPublicJwk = null;
  const peers = {};
  const peerInit = {};
  const sendQueues = {};

  function bytes(value) {
    return encoder.encode(value);
  }

  function b64(bytesValue) {
    let binary = "";
    bytesValue.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary);
  }

  function fromB64(value) {
    const binary = atob(value);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }

  function zero(value) {
    if (!value) return;
    if (value instanceof Uint8Array) {
      value.fill(0);
      return;
    }
    if (value instanceof ArrayBuffer) {
      new Uint8Array(value).fill(0);
    }
  }

  async function digest(value) {
    const input = typeof value === "string" ? bytes(value) : value;
    const hash = await crypto.subtle.digest("SHA-256", input);
    return new Uint8Array(hash);
  }

  async function deriveRoomKey(passphrase, room) {
    const passBytes = bytes(passphrase);
    const salt = await digest("roomoff|max-paranoia|" + room);

    const pbkdfBase = await crypto.subtle.importKey(
      "raw",
      passBytes,
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    zero(passBytes);

    const rawBits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      pbkdfBase,
      256
    );
    zero(salt);

    const rawBytes = new Uint8Array(rawBits);
    roomKey = await crypto.subtle.importKey(
      "raw",
      rawBytes,
      { name: "HKDF" },
      false,
      ["deriveBits", "deriveKey"]
    );
    zero(rawBytes);
    zero(rawBits);

    localKeyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );
    localPublicJwk = await crypto.subtle.exportKey("jwk", localKeyPair.publicKey);
    return true;
  }

  function hasRoomKey() {
    return !!roomKey && !!localPublicJwk;
  }

  function publicKey() {
    return localPublicJwk;
  }

  async function importPeerKey(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
  }

  async function deriveRaw(material, info) {
    const salt = await digest("roomoff|hkdf|salt");
    const key = await crypto.subtle.importKey("raw", material, "HKDF", false, ["deriveBits"]);
    const raw = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: bytes(info) },
      key,
      256
    );
    zero(salt);
    zero(material);
    return new Uint8Array(raw);
  }

  async function deriveBitsKey(info) {
    return crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: await digest("roomoff|room|salt"),
        info: bytes(info)
      },
      roomKey,
      256
    );
  }

  async function ensurePeer(peerId, peerPublicJwk, localId) {
    if (!roomKey || !localKeyPair || !peerPublicJwk) return null;
    if (peers[peerId]) return peers[peerId];
    if (peerInit[peerId]) return peerInit[peerId];

    peerInit[peerId] = (async () => {
      const imported = await importPeerKey(peerPublicJwk);
      const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: imported },
        localKeyPair.privateKey,
        256
      );
      const roomBits = await deriveBitsKey("peer|" + [localId, peerId].sort().join("|"));
      const combined = new Uint8Array(64);
      combined.set(new Uint8Array(sharedBits), 0);
      combined.set(new Uint8Array(roomBits), 32);
      const ordered = [localId, peerId].sort();
      const entry = {
        sendIndex: 0,
        receiveIndex: 0,
        // NOTE: sendSeed of A ("send|A|B") intentionally equals receiveSeed of B
        // ("send|A|B") thanks to the fixed "send|localId|peerId" ordering below.
        // This symmetry is what lets the ratchet below stay correct on both
        // sides without a separate "receive" derivation branch.
        sendSeed: await deriveRaw(combined.slice(), "send|" + localId + "|" + peerId),
        receiveSeed: await deriveRaw(combined.slice(), "send|" + peerId + "|" + localId),
        pairId: ordered.join("|")
      };
      zero(combined);
      zero(sharedBits);
      zero(roomBits);
      peers[peerId] = entry;
      delete peerInit[peerId];
      return entry;
    })();

    return peerInit[peerId];
  }

  /**
   * True one-way ratchet (forward-secret): derives the message key from the
   * CURRENT seed, then destructively replaces that seed with a fresh one
   * derived from itself, zeroing the old bytes. The seed can no longer
   * regenerate past keys once advanced — compromising memory at time T only
   * exposes messages from T onward, never earlier ones.
   *
   * `direction` is always the literal string "send" by design (see the note
   * in ensurePeer above) — do NOT change this to reflect "send"/"receive"
   * semantically, or you will desynchronize the two sides' derivations.
   */
  async function ratchetStep(peer, seedField) {
    const seed = peer[seedField];
    const raw = await deriveRaw(seed.slice(), "ratchet-key|" + peer.pairId + "|send");
    const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
    zero(raw);

    const nextSeed = await deriveRaw(seed.slice(), "ratchet-advance|" + peer.pairId + "|send");
    zero(peer[seedField]);
    peer[seedField] = nextSeed;

    return key;
  }

  async function encryptPacket(peerId, peerPublicJwk, localId, packet) {
    const previous = sendQueues[peerId] || Promise.resolve();
    const current = previous.then(async () => {
      const peer = await ensurePeer(peerId, peerPublicJwk, localId);
      if (!peer) return null;
      peer.sendIndex += 1;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = bytes(JSON.stringify(packet));
      const key = await ratchetStep(peer, "sendSeed");
      const cipher = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: bytes(peer.pairId + "|" + peer.sendIndex) },
        key,
        plaintext
      );
      zero(plaintext);
      const cipherBytes = new Uint8Array(cipher);
      const sealed = { type: "secure-message", v: 1, i: peer.sendIndex, iv: b64(iv), body: b64(cipherBytes) };
      zero(iv);
      zero(cipherBytes);
      zero(cipher);
      return sealed;
    });
    sendQueues[peerId] = current.catch(() => {});
    return current;
  }

  async function decryptPacket(peerId, peerPublicJwk, localId, packet) {
    const peer = await ensurePeer(peerId, peerPublicJwk, localId);
    if (!peer || packet.type !== "secure-message") return null;
    const index = Number(packet.i || 0);
    if (!index || index <= peer.receiveIndex) return null;
    const iv = fromB64(packet.iv);
    const body = fromB64(packet.body);

    // Advance the ratchet one step per index between what we've already
    // consumed and this message's index (covers dropped/out-of-order
    // messages), keeping only the key matching this packet's index.
    const steps = index - peer.receiveIndex;
    let key;
    for (let s = 0; s < steps; s += 1) {
      key = await ratchetStep(peer, "receiveSeed");
    }

    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: bytes(peer.pairId + "|" + index) },
      key,
      body
    );
    peer.receiveIndex = index;
    const plainBytes = new Uint8Array(plain);
    const text = decoder.decode(plainBytes);
    zero(iv);
    zero(body);
    zero(plainBytes);
    zero(plain);
    return JSON.parse(text);
  }

  function destroy() {
    Object.keys(peers).forEach((peerId) => {
      if (peers[peerId]) {
        if (peers[peerId].sendSeed) zero(peers[peerId].sendSeed);
        if (peers[peerId].receiveSeed) zero(peers[peerId].receiveSeed);
      }
      delete peers[peerId];
    });
    Object.keys(peerInit).forEach((peerId) => delete peerInit[peerId]);
    Object.keys(sendQueues).forEach((peerId) => delete sendQueues[peerId]);
    roomKey = null;
    localKeyPair = null;
    localPublicJwk = null;
  }

  return {
    deriveRoomKey,
    hasRoomKey,
    publicKey,
    encryptPacket,
    decryptPacket,
    zero,
    destroy,
    iterations
  };
})();
