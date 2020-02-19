import BN from "bn.js";

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
type FeatureBits = {
  word_length: number; 
  option_data_loss_protect?: Feature;
  initial_routing_sync?: Feature;
  option_upfront_shutdown_script?: Feature;
  gossip_queries?: Feature;
  var_onion_optin?: Feature;
  gossip_queries_ex?: Feature;
  option_static_remotekey?: Feature;
  payment_secret?: Feature;
  basic_mpp?: Feature;
  option_support_large_channel?: Feature;
  extra_bits?: {
    start_bit: number;
    bits: boolean[];
    has_required?: boolean;
  };
}
type Feature = {
  required?: boolean;
  supported?: boolean;
};
type Network = {
  [index: string]: any;
  bech32: string;
  pubKeyHash: number;
  scriptHash: number;
  validWitnessVersions: number[];
};

// Start exports
export declare type TagData = string | number | RoutingInfo | FallbackAddress | FeatureBits;
export declare type PaymentRequestObject = {
  paymentRequest?: string;
  complete?: boolean;
  prefix?: string;
  wordsTemp?: string;
  network?: Network;
  satoshis?: number | null;
  millisatoshis?: string | null;
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
export declare function decode(paymentRequest: string, network?: Network): PaymentRequestObject;
export declare function sign(inputPayReqObj: PaymentRequestObject, inputPrivateKey: string | Buffer): PaymentRequestObject;
export declare function satToHrp(satoshis: number | string): string;
export declare function millisatToHrp(millisatoshis: number | string): string;
export declare function hrpToSat(hrpString: string, outputString?: boolean): string | BN;
export declare function hrpToMillisat(hrpString: string, outputString?: boolean): string | BN;
