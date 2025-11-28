/**
 * Custom error class for decryption failures
 * Ensures no secret leakage in error messages
 */
export class DecryptionError extends Error {
    constructor(message = 'Decryption failed') {
        super(message);
        this.name = 'DecryptionError';
        Object.setPrototypeOf(this, DecryptionError.prototype);
    }
}
//# sourceMappingURL=types.js.map