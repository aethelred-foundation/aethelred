/**
 * Offline Transaction Signing module for Aethelred TypeScript SDK.
 *
 * This module enables signing transactions without network access,
 * useful for:
 * - Air-gapped signing environments
 * - Hardware wallet integration
 * - Batch transaction preparation
 * - Cold storage operations
 *
 * @module tx/offline
 */

import { sha256 } from '../crypto/index';

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Transaction message types
 */
export type MessageType =
  | 'MsgSubmitJob'
  | 'MsgRegisterModel'
  | 'MsgCreateSeal'
  | 'MsgRevokeSeal'
  | 'MsgSubmitVerification'
  | 'MsgDelegate'
  | 'MsgUndelegate'
  | 'MsgBeginRedelegate'
  | 'MsgSend';

/**
 * Coin amount
 */
export interface Coin {
  denom: string;
  amount: string;
}

/**
 * Transaction fee
 */
export interface Fee {
  amount: Coin[];
  gasLimit: string;
  payer?: string;
  granter?: string;
}

/**
 * Public key types
 */
export interface PublicKey {
  typeUrl: string;
  value: Uint8Array;
}

/**
 * Signer info for transactions
 */
export interface SignerInfo {
  publicKey: PublicKey | null;
  modeInfo: {
    single?: { mode: string };
    multi?: { bitarray: { extraBitsStored: number; elems: Uint8Array }; modeInfos: SignerInfo[] };
  };
  sequence: string;
}

/**
 * Auth info containing signer and fee
 */
export interface AuthInfo {
  signerInfos: SignerInfo[];
  fee: Fee;
}

/**
 * Transaction body
 */
export interface TxBody {
  messages: Message[];
  memo: string;
  timeoutHeight: string;
  extensionOptions: unknown[];
  nonCriticalExtensionOptions: unknown[];
}

/**
 * Generic message interface
 */
export interface Message {
  typeUrl: string;
  value: Record<string, unknown>;
}

/**
 * Sign document for direct signing
 */
export interface SignDoc {
  bodyBytes: Uint8Array;
  authInfoBytes: Uint8Array;
  chainId: string;
  accountNumber: string;
}

/**
 * Signed transaction
 */
export interface SignedTx {
  body: TxBody;
  authInfo: AuthInfo;
  signatures: Uint8Array[];
}

/**
 * Account info needed for signing
 */
export interface AccountInfo {
  address: string;
  accountNumber: string;
  sequence: string;
  publicKey?: PublicKey;
}

// ============================================================================
// Message Builders
// ============================================================================

/**
 * Build a MsgSubmitJob message
 */
export function buildMsgSubmitJob(params: {
  sender: string;
  modelHash: string;
  inputHash: string;
  proofType: 'TEE' | 'ZKML' | 'HYBRID';
  purpose: string;
  fee?: Coin;
  priority?: number;
}): Message {
  return {
    typeUrl: '/aethelred.pouw.v1.MsgSubmitJob',
    value: {
      sender: params.sender,
      model_hash: params.modelHash,
      input_hash: params.inputHash,
      proof_type: `PROOF_TYPE_${params.proofType}`,
      purpose: params.purpose,
      fee: params.fee || { denom: 'uaeth', amount: '1000' },
      priority: params.priority || 0,
    },
  };
}

/**
 * Build a MsgRegisterModel message
 */
export function buildMsgRegisterModel(params: {
  owner: string;
  modelHash: string;
  name: string;
  description: string;
  version: string;
  architecture: string;
}): Message {
  return {
    typeUrl: '/aethelred.pouw.v1.MsgRegisterModel',
    value: {
      owner: params.owner,
      model_hash: params.modelHash,
      name: params.name,
      description: params.description,
      version: params.version,
      architecture: params.architecture,
    },
  };
}

/**
 * Build a MsgSend message (token transfer)
 */
export function buildMsgSend(params: { fromAddress: string; toAddress: string; amount: Coin[] }): Message {
  return {
    typeUrl: '/cosmos.bank.v1beta1.MsgSend',
    value: {
      from_address: params.fromAddress,
      to_address: params.toAddress,
      amount: params.amount,
    },
  };
}

/**
 * Build a MsgDelegate message
 */
export function buildMsgDelegate(params: { delegatorAddress: string; validatorAddress: string; amount: Coin }): Message {
  return {
    typeUrl: '/cosmos.staking.v1beta1.MsgDelegate',
    value: {
      delegator_address: params.delegatorAddress,
      validator_address: params.validatorAddress,
      amount: params.amount,
    },
  };
}

/**
 * Build a MsgUndelegate message
 */
export function buildMsgUndelegate(params: {
  delegatorAddress: string;
  validatorAddress: string;
  amount: Coin;
}): Message {
  return {
    typeUrl: '/cosmos.staking.v1beta1.MsgUndelegate',
    value: {
      delegator_address: params.delegatorAddress,
      validator_address: params.validatorAddress,
      amount: params.amount,
    },
  };
}

// ============================================================================
// Offline Transaction Builder
// ============================================================================

/**
 * Offline transaction builder for air-gapped signing
 */
export class OfflineTransactionBuilder {
  private chainId: string;
  private messages: Message[] = [];
  private memo: string = '';
  private timeoutHeight: string = '0';
  private fee: Fee;

  constructor(chainId: string, defaultFee?: Fee) {
    this.chainId = chainId;
    this.fee = defaultFee || {
      amount: [{ denom: 'uaeth', amount: '5000' }],
      gasLimit: '200000',
    };
  }

  /**
   * Add a message to the transaction
   */
  addMessage(message: Message): this {
    this.messages.push(message);
    return this;
  }

  /**
   * Set the memo
   */
  setMemo(memo: string): this {
    this.memo = memo;
    return this;
  }

  /**
   * Set the timeout height
   */
  setTimeoutHeight(height: string | number): this {
    this.timeoutHeight = String(height);
    return this;
  }

  /**
   * Set the fee
   */
  setFee(fee: Fee): this {
    this.fee = fee;
    return this;
  }

  /**
   * Build the transaction body
   */
  buildTxBody(): TxBody {
    return {
      messages: this.messages,
      memo: this.memo,
      timeoutHeight: this.timeoutHeight,
      extensionOptions: [],
      nonCriticalExtensionOptions: [],
    };
  }

  /**
   * Build the auth info
   */
  buildAuthInfo(signerInfos: SignerInfo[]): AuthInfo {
    return {
      signerInfos,
      fee: this.fee,
    };
  }

  /**
   * Build the sign document
   */
  buildSignDoc(accountInfo: AccountInfo): SignDoc {
    const signerInfo: SignerInfo = {
      publicKey: accountInfo.publicKey || null,
      modeInfo: {
        single: { mode: 'SIGN_MODE_DIRECT' },
      },
      sequence: accountInfo.sequence,
    };

    const txBody = this.buildTxBody();
    const authInfo = this.buildAuthInfo([signerInfo]);

    // In a real implementation, these would be protobuf-encoded
    // For demonstration, we use JSON
    const bodyBytes = new TextEncoder().encode(JSON.stringify(txBody));
    const authInfoBytes = new TextEncoder().encode(JSON.stringify(authInfo));

    return {
      bodyBytes,
      authInfoBytes,
      chainId: this.chainId,
      accountNumber: accountInfo.accountNumber,
    };
  }

  /**
   * Get the bytes to sign
   */
  async getSignBytes(signDoc: SignDoc): Promise<Uint8Array> {
    // Concatenate all parts of the sign doc
    const signDocBytes = new TextEncoder().encode(
      JSON.stringify({
        bodyBytes: Array.from(signDoc.bodyBytes),
        authInfoBytes: Array.from(signDoc.authInfoBytes),
        chainId: signDoc.chainId,
        accountNumber: signDoc.accountNumber,
      })
    );

    // Hash with SHA-256
    return sha256(signDocBytes);
  }

  /**
   * Build the signed transaction
   */
  buildSignedTx(signDoc: SignDoc, signatures: Uint8Array[]): SignedTx {
    const txBody: TxBody = JSON.parse(new TextDecoder().decode(signDoc.bodyBytes));
    const authInfo: AuthInfo = JSON.parse(new TextDecoder().decode(signDoc.authInfoBytes));

    return {
      body: txBody,
      authInfo,
      signatures,
    };
  }

  /**
   * Serialize the signed transaction for broadcast
   */
  serializeForBroadcast(signedTx: SignedTx): Uint8Array {
    // In production, this would use protobuf encoding
    // For demonstration, we use JSON
    const txJson = JSON.stringify({
      body: signedTx.body,
      auth_info: signedTx.authInfo,
      signatures: signedTx.signatures.map((sig) => Array.from(sig)),
    });

    return new TextEncoder().encode(txJson);
  }

  /**
   * Get the transaction as base64 for RPC broadcast
   */
  getBase64ForBroadcast(signedTx: SignedTx): string {
    const bytes = this.serializeForBroadcast(signedTx);
    return btoa(String.fromCharCode(...bytes));
  }

  /**
   * Clear all messages
   */
  clear(): this {
    this.messages = [];
    this.memo = '';
    this.timeoutHeight = '0';
    return this;
  }
}

// ============================================================================
// Offline Signer Interface
// ============================================================================

/**
 * Interface for offline signers (hardware wallets, air-gapped systems)
 */
export interface OfflineSigner {
  /**
   * Get accounts available for signing
   */
  getAccounts(): Promise<AccountInfo[]>;

  /**
   * Sign a transaction
   */
  sign(signDoc: SignDoc): Promise<Uint8Array>;

  /**
   * Sign raw bytes (for advanced use)
   */
  signBytes?(bytes: Uint8Array): Promise<Uint8Array>;
}

/**
 * Simple in-memory signer for testing
 */
export class MemorySigner implements OfflineSigner {
  private privateKey: Uint8Array;
  private publicKey: Uint8Array;
  private address: string;
  private accountNumber: string;
  private sequence: string;

  constructor(params: {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    address: string;
    accountNumber: string;
    sequence: string;
  }) {
    this.privateKey = params.privateKey;
    this.publicKey = params.publicKey;
    this.address = params.address;
    this.accountNumber = params.accountNumber;
    this.sequence = params.sequence;
  }

  async getAccounts(): Promise<AccountInfo[]> {
    return [
      {
        address: this.address,
        accountNumber: this.accountNumber,
        sequence: this.sequence,
        publicKey: {
          typeUrl: '/cosmos.crypto.secp256k1.PubKey',
          value: this.publicKey,
        },
      },
    ];
  }

  async sign(signDoc: SignDoc): Promise<Uint8Array> {
    // Get the bytes to sign
    const builder = new OfflineTransactionBuilder(signDoc.chainId);
    const signBytes = await builder.getSignBytes(signDoc);

    // Sign using SubtleCrypto (ECDSA with secp256k1)
    // Note: secp256k1 is not natively supported in SubtleCrypto
    // In production, use a library like @noble/secp256k1

    // Placeholder: return hash of sign bytes XOR'd with private key
    const signature = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      signature[i] = signBytes[i % signBytes.length] ^ this.privateKey[i % this.privateKey.length];
    }

    return signature;
  }

  async signBytes(bytes: Uint8Array): Promise<Uint8Array> {
    // Hash and sign
    const hash = sha256(bytes);
    const signature = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
      signature[i] = hash[i % hash.length] ^ this.privateKey[i % this.privateKey.length];
    }
    return signature;
  }

  /**
   * Increment sequence for next transaction
   */
  incrementSequence(): void {
    this.sequence = String(BigInt(this.sequence) + 1n);
  }
}

// ============================================================================
// Batch Transaction Builder
// ============================================================================

/**
 * Build multiple transactions for batch signing
 */
export class BatchTransactionBuilder {
  private chainId: string;
  private transactions: OfflineTransactionBuilder[] = [];

  constructor(chainId: string) {
    this.chainId = chainId;
  }

  /**
   * Add a new transaction to the batch
   */
  addTransaction(): OfflineTransactionBuilder {
    const tx = new OfflineTransactionBuilder(this.chainId);
    this.transactions.push(tx);
    return tx;
  }

  /**
   * Get all transactions
   */
  getTransactions(): OfflineTransactionBuilder[] {
    return this.transactions;
  }

  /**
   * Build sign documents for all transactions
   */
  buildAllSignDocs(accountInfo: AccountInfo): SignDoc[] {
    const signDocs: SignDoc[] = [];
    let currentSequence = BigInt(accountInfo.sequence);

    for (const tx of this.transactions) {
      const signDoc = tx.buildSignDoc({
        ...accountInfo,
        sequence: currentSequence.toString(),
      });
      signDocs.push(signDoc);
      currentSequence++;
    }

    return signDocs;
  }

  /**
   * Sign all transactions with the given signer
   */
  async signAll(signer: OfflineSigner): Promise<SignedTx[]> {
    const accounts = await signer.getAccounts();
    if (accounts.length === 0) {
      throw new Error('No accounts available for signing');
    }

    const accountInfo = accounts[0];
    const signDocs = this.buildAllSignDocs(accountInfo);
    const signedTxs: SignedTx[] = [];

    for (const signDoc of signDocs) {
      const signature = await signer.sign(signDoc);
      const tx = this.transactions[signDocs.indexOf(signDoc)];
      signedTxs.push(tx.buildSignedTx(signDoc, [signature]));
    }

    return signedTxs;
  }

  /**
   * Clear all transactions
   */
  clear(): this {
    this.transactions = [];
    return this;
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Estimate gas for a transaction
 */
export function estimateGas(messages: Message[]): string {
  // Base gas
  let gas = 50000;

  // Add gas per message
  for (const msg of messages) {
    switch (msg.typeUrl) {
      case '/aethelred.pouw.v1.MsgSubmitJob':
        gas += 100000; // Compute jobs need more gas
        break;
      case '/aethelred.pouw.v1.MsgRegisterModel':
        gas += 75000;
        break;
      case '/cosmos.bank.v1beta1.MsgSend':
        gas += 50000;
        break;
      case '/cosmos.staking.v1beta1.MsgDelegate':
      case '/cosmos.staking.v1beta1.MsgUndelegate':
        gas += 100000;
        break;
      default:
        gas += 50000;
    }
  }

  return String(gas);
}

/**
 * Calculate fee from gas
 */
export function calculateFee(gas: string, gasPrice: string = '0.025'): Fee {
  const gasNum = BigInt(gas);
  const priceNum = Math.floor(parseFloat(gasPrice) * 1000000); // Convert to micro-units
  const amount = (gasNum * BigInt(priceNum)) / BigInt(1000000);

  return {
    amount: [{ denom: 'uaeth', amount: amount.toString() }],
    gasLimit: gas,
  };
}

// ============================================================================
// Exports
// ============================================================================

export function createOfflineBuilder(chainId: string): OfflineTransactionBuilder {
  return new OfflineTransactionBuilder(chainId);
}

export function createBatchBuilder(chainId: string): BatchTransactionBuilder {
  return new BatchTransactionBuilder(chainId);
}
