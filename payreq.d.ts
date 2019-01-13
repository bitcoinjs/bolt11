import * as BN from "bn.js";

type RoutingInfo = Array<{
  pubkey: string;
  short_channel_id: string;
  fee_base_msat: number;
  fee_proportional_millionths: number;
  cltv_expiry_delta: number;
}>;
type FallbackAddress = {
  code: number;
  address: string;
  addressHash: string;
};

// Start exports
export declare type TagData = string | number | RoutingInfo | FallbackAddress;
export declare type PaymentRequestObject = {
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
    data: TagData;
  }>;
};
export declare function encode(inputData: PaymentRequestObject, addDefaults?: boolean): PaymentRequestObject;
export declare function decode(paymentRequest: string): PaymentRequestObject;
export declare function sign(inputPayReqObj: PaymentRequestObject, inputPrivateKey: string | Buffer): PaymentRequestObject;
export declare function satToHrp(satoshis: number | string): string;
export declare function millisatToHrp(millisatoshis: number | string): string;
export declare function hrpToSat(hrpString: string, outputString?: boolean): string | BN;
export declare function hrpToMillisat(hrpString: string, outputString?: boolean): string | BN;
