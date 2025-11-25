declare module 'fido2-lib' {
  export class Fido2Lib {
    constructor(config?: {
      timeout?: number;
      rpId?: string;
      rpName?: string;
      rpIcon?: string;
      challengeSize?: number;
      attestation?: 'none' | 'indirect' | 'direct';
      cryptoParams?: number[];
      authenticatorAttachment?: 'platform' | 'cross-platform';
      authenticatorRequireResidentKey?: boolean;
      authenticatorUserVerification?: 'required' | 'preferred' | 'discouraged';
    });

    attestationOptions(): Promise<{
      challenge: ArrayBuffer;
      rp: {
        name: string;
        id?: string;
      };
      user: {
        id: ArrayBuffer;
        name: string;
        displayName: string;
      };
      pubKeyCredParams: Array<{
        type: string;
        alg: number;
      }>;
      timeout?: number;
      attestation?: string;
      authenticatorSelection?: any;
    }>;

    attestationResult(
      result: any,
      expected: {
        challenge: string;
        origin: string;
        factor?: string;
      }
    ): Promise<any>;

    assertionOptions(): Promise<{
      challenge: ArrayBuffer;
      timeout?: number;
      rpId?: string;
      allowCredentials?: Array<{
        type: string;
        id: ArrayBuffer;
      }>;
      userVerification?: string;
    }>;

    assertionResult(
      result: any,
      expected: {
        challenge: string;
        origin: string;
        factor?: string;
        publicKey?: string;
        prevCounter?: number;
        userHandle?: string;
      }
    ): Promise<any>;
  }
}

