import { describe, it, expect } from 'vitest';
import { PublicKeyOnlyIdentity, buildIdentity } from '../buildIdentity';
import { Ed25519PublicKey } from '@dfinity/identity';
import { fromHex } from '@dfinity/agent';

describe('identity helpers', () => {
  describe('PublicKeyOnlyIdentity', () => {
    it('should create an identity with a public key', () => {
      const mockPublicKey = Ed25519PublicKey.fromDer(
        fromHex(
          '302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        ),
      );
      const identity = new PublicKeyOnlyIdentity(mockPublicKey);
      expect(identity.getPublicKey()).toBe(mockPublicKey);
    });

    it('should throw error when trying to sign', async () => {
      const mockPublicKey = Ed25519PublicKey.fromDer(
        fromHex(
          '302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        ),
      );
      const identity = new PublicKeyOnlyIdentity(mockPublicKey);
      await expect(identity.sign(new ArrayBuffer(0))).rejects.toThrow(
        'Cannot sign with public key only identity',
      );
    });
  });

  describe('buildIdentity', () => {
    it('should create a PublicKeyOnlyIdentity from a hex string', () => {
      const pubkey =
        '302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
      const identity = buildIdentity(pubkey);
      expect(identity).toBeInstanceOf(PublicKeyOnlyIdentity);
      expect(identity.getPublicKey()).toBeInstanceOf(Ed25519PublicKey);
    });
  });
});
