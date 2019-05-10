import { createHash, randomBytes } from 'crypto';
import { AES, enc } from 'crypto-js';
import {
  createGroup,
  decrypt,
  encrypt,
  fromFrontier,
  hashUp,
  merge,
  TreeKEM,
  TreeKEMCiphertext,
  equal
} from 'eth-treekem';
import {
  cbcEncrypt,
  decrypt as cbcDecrypt,
  EthKeyPair
} from 'eth-treekem/build/main/lib/eth-crypto';
import iota from 'eth-treekem/build/main/lib/iota';
import tm from 'eth-treekem/build/main/lib/tree-math';
import { X3DH_Receiving, X3DH_Sending } from 'eth-x3dh';
import { range } from 'ramda';
import { v4 } from 'uuid';
import { ECKEMCipher } from 'eth-treekem/build/main/lib/eckem';

const { Utf8 } = enc;

const hash = () =>
  createHash('sha256')
    .update(randomBytes(16))
    .digest('hex');
const createKeyPair = () => iota(hash());

interface MessagePayload {
  readonly text: string;
  readonly timestamp: number;
  readonly chatId: string;
}

interface TreeKEMMessage {
  readonly ct: TreeKEMCiphertext;
  readonly index: number;
  readonly payload: string;
}

interface TreeKEMBundle {
  readonly treekem: TreeKEM;
  readonly chatId: string;
}

interface X3DHPayload {
  readonly ciphertext: ECKEMCipher;
  readonly oneTimePublicKey: string;
}

interface X3DHBundle {
  readonly publicIdKey: string;
  readonly publicEphKey: string;
  readonly publicOTKeys: string[];
}

interface OneTimeKeys {
  readonly [publicKey: string]: EthKeyPair;
}

interface KeyStore {
  readonly ephemeral: EthKeyPair;
  readonly identity: EthKeyPair;
  readonly oneTimeKeys: OneTimeKeys;
}

function oneTimeKeys(): OneTimeKeys {
  return range(0, 20)
    .map(() => createKeyPair())
    .reduce((acc, kp) => {
      return {
        ...acc,
        [kp.publicKey]: kp
      };
    }, {});
}

function createKeyStore(): KeyStore {
  return {
    ephemeral: createKeyPair(),
    identity: createKeyPair(),
    oneTimeKeys: oneTimeKeys()
  };
}

export function refreshTransientKeys(keyStore: KeyStore): KeyStore {
  return {
    ...keyStore,
    ephemeral: createKeyPair(),
    oneTimeKeys: oneTimeKeys()
  };
}

function createX3DHBundle(keyStore: KeyStore): X3DHBundle {
  return {
    publicIdKey: keyStore.identity.publicKey,
    publicEphKey: keyStore.ephemeral.publicKey,
    publicOTKeys: Object.keys(keyStore.oneTimeKeys)
  };
}

async function x3dhSend(keyStore: KeyStore, bundle: X3DHBundle): Promise<any> {
  return X3DH_Sending(
    keyStore.identity.privateKey,
    keyStore.ephemeral.privateKey,
    bundle.publicIdKey,
    bundle.publicEphKey,
    bundle.publicOTKeys[0]
  );
}

async function x3dhReceive(
  keyStore: KeyStore,
  bundle: X3DHBundle,
  x3dhPayload: X3DHPayload
): Promise<any> {
  return X3DH_Receiving(
    keyStore.identity.privateKey,
    keyStore.ephemeral.privateKey,
    bundle.publicIdKey,
    bundle.publicEphKey,
    keyStore.oneTimeKeys[x3dhPayload.oneTimePublicKey].privateKey
  );
}

async function encryptTreeKEMMessage(
  treekem: TreeKEM,
  text: string
): Promise<{ readonly treekem: TreeKEM; readonly message: TreeKEMMessage }> {
  const s = hash();
  const ct = await encrypt(treekem, s);
  const updated = merge(
    merge(treekem, ct.nodes),
    await hashUp(treekem.index, treekem.size, s)
  );
  const root = tm.root(treekem.size);
  const payload = AES.encrypt(
    JSON.stringify({
      text,
      timestamp: new Date().getTime()
    }),
    updated.nodes[root].secret
  ).toString();
  const message: TreeKEMMessage = {
    ct,
    index: updated.index,
    payload,
  };

  return {
    message,
    treekem: updated
  };
}

async function decryptTreeKEMMessage(
  treekem: TreeKEM,
  message: TreeKEMMessage
): Promise<TreeKEM> {
  const { secret, nodes, size } = await decrypt(
    treekem,
    message.index,
    message.ct.ciphertexts
  );
  const updatedTreekem = merge(merge(treekem, message.ct.nodes), nodes, size);
  const plaintext = AES.decrypt(message.payload, secret).toString(Utf8);
  const { text: txt, timestamp }: MessagePayload = JSON.parse(plaintext);
  console.log(txt);
  console.log(timestamp);
  return updatedTreekem;
}

async function addMember(
  treekem: TreeKEM
): Promise<{ readonly existing: TreeKEM; readonly newMember: TreeKEM, readonly message: TreeKEMMessage }> {
  const secret = hash();
  const newMember = await fromFrontier(treekem.size, treekem.nodes, secret);

  const ct = await encrypt(newMember, secret);
  const pt = JSON.parse(
    JSON.stringify(await decrypt(treekem, newMember.index, ct.ciphertexts))
  );

  const root = tm.root(newMember.size);
  const payload = AES.encrypt(
    JSON.stringify({
      text: 'Member added',
      timestamp: new Date().getTime()
    }),
    newMember.nodes[root].secret
  ).toString();

  return {
    existing: merge(merge(treekem, ct.nodes), pt.nodes, pt.size),
    message: {
        ct,
        index: newMember.index,
        payload,
    },
    newMember,
  };
}

async function messagingTest() {
  const keyStore1: KeyStore = createKeyStore();
  const bundle1: X3DHBundle = createX3DHBundle(keyStore1);

  const keyStore2: KeyStore = createKeyStore();
  const bundle2: X3DHBundle = createX3DHBundle(keyStore2); // This would be pulled from a server

  const send = await x3dhSend(keyStore1, bundle2);

  const members = await createGroup(2);

  const tkemBundle: TreeKEMBundle = {
    chatId: v4(),
    treekem: members[1]
  };

  const encryptedBundle = cbcEncrypt(JSON.stringify(tkemBundle), send);
  const x3dhPayload: X3DHPayload = {
    ciphertext: encryptedBundle,
    oneTimePublicKey: bundle2.publicOTKeys[0]
  };
  const receive = await x3dhReceive(keyStore2, bundle1, x3dhPayload);

  let { treekem: member2, chatId }: TreeKEMBundle = JSON.parse(
    cbcDecrypt(x3dhPayload.ciphertext, receive)
  );
  let member1 = members[0];

  const { treekem: member1Updated, message } = await encryptTreeKEMMessage(
    member1,
    'This is a test message'
  );
  member1 = member1Updated;

  member2 = await decryptTreeKEMMessage(member2, message);

  const { existing, newMember, message: message3 } = await addMember(member1);
  member1 = existing;
  console.log(equal(existing, newMember));

  const keyStore3 = createKeyStore();
  const bundle3 = createX3DHBundle(keyStore3);

  const send3 = await x3dhSend(keyStore2, bundle3);
  const tkemBundle3: TreeKEMBundle = {
    chatId,
    treekem: newMember
  };

  const encryptedBundle3 = cbcEncrypt(JSON.stringify(tkemBundle3), send3);
  const x3dhPayload3: X3DHPayload = {
    ciphertext: encryptedBundle3,
    oneTimePublicKey: bundle3.publicOTKeys[0]
  };
  const receive3 = await x3dhReceive(
    keyStore3,
    bundle2,
    x3dhPayload3
  );
  let { treekem: member3, chatId: chatId3 }: TreeKEMBundle = JSON.parse(
    cbcDecrypt(x3dhPayload3.ciphertext, receive3)
  );
  console.log(chatId === chatId3);
  console.log(member3);

  member2 = await decryptTreeKEMMessage(member2, message3);
}

messagingTest().then(console.log);
