interface ValidResult  {
    valid: true,
    address: string
}

interface InvalidResult  {
    valid: false,
}

export type ValidationResult = ValidResult | InvalidResult;

export declare function validateAddress(address: string): ValidationResult;
