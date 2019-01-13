import * as BN from "bn.js";
type PaymentRequestObject = {
  paymentRequest?: string;
  complete?: boolean;
  prefix?: string;
  wordsTemp?: string;
  coinType?: string;
  satoshis?: number;
  millisatoshis?: string;
  timestamp?: number;
  timestampString?: string;
  timeExpireDate?: number;
  timeExpireDateString?: string;
  payeeNodeKey?: string;
  signature?: string;
  recoveryFlag?: number;
  tags: Array<{
    tagName: string;
    data: any;
  }>;
};
declare function encode(inputData: PaymentRequestObject, addDefaults?: boolean): PaymentRequestObject;
declare function decode(paymentRequest: string): PaymentRequestObject;
declare function sign(inputPayReqObj: PaymentRequestObject, inputPrivateKey: string | Buffer): PaymentRequestObject;
declare function satToHrp(satoshis: number | string): string;
declare function millisatToHrp(millisatoshis: number | string): string;
declare function hrpToSat(hrpString: string, outputString?: boolean): string | BN;
declare function hrpToMillisat(hrpString: string, outputString?: boolean): string | BN;
export { encode, decode, sign, satToHrp, millisatToHrp, hrpToSat, hrpToMillisat };
