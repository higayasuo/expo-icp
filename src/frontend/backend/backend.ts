import {
  DFX_NETWORK,
  LOCAL_IP_ADDRESS,
  CANISTER_ID_BACKEND,
} from '@/constants/env.generated';
import { idlFactory, _SERVICE } from './backend.did';
import { Identity, ActorSubclass } from '@dfinity/agent';
import { CanisterManager } from 'canister-manager';

export const createBackend = (
  identity: Identity | undefined,
): ActorSubclass<_SERVICE> => {
  const canisterManager = new CanisterManager({
    dfxNetwork: DFX_NETWORK,
    localIPAddress: LOCAL_IP_ADDRESS,
  });
  return canisterManager.createActor<_SERVICE>({
    canisterId: CANISTER_ID_BACKEND,
    interfaceFactory: idlFactory,
    identity,
  });
};
