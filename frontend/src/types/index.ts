export type Operation='Маскирование'|'Демаскирование';
export type AuditRow={time:string;payloadId:string;operation:Operation;latency:number;status:number;types:string[];tokens:number;retryAfter?:string};
export type ProcessResult={result:string;latency:number;status:number;retryAfter?:string};
