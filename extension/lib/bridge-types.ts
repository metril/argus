export interface ConnectSpec { page: string; list: string[]; all: boolean }

export interface CookieIn {
  name: string; value: string; domain?: string; path?: string; secure?: boolean;
  http_only?: boolean; same_site?: string; expiration_date?: number;
}
export interface CookieOut {
  name: string; value: string; domain: string; path: string; secure: boolean;
  http_only: boolean; same_site?: string; expiration_date?: number;
}
export type CookieReq =
  | { op: 'list'; url: string; name?: string }
  | { op: 'set'; url: string; cookie: CookieIn }
  | { op: 'delete'; url: string; name: string };

export interface XhrMeta {
  op: 'xhr'; script: string; relay: string; connect: ConnectSpec;
  method: string; url: string; headers: [string, string][];
  redirect: 'follow' | 'error' | 'manual'; timeout?: number; hasBody?: boolean;
}
export interface CookieMeta { op: 'cookie'; script: string; relay: string; connect: ConnectSpec; cookie: CookieReq }
export type JobMeta = XhrMeta | CookieMeta;

export type ErrKind = 'denied' | 'network' | 'timeout' | 'too_large';
export type ErrCode = 'connect_denied' | 'network' | 'timeout' | 'too_large' | 'bad_request' | 'permission';
export interface ErrBody { kind: ErrKind; code: ErrCode; message: string }

export class BridgeError extends Error {
  constructor(public kind: ErrKind, public code: ErrCode, message: string) { super(message); }
}

export interface HostsMsg { t: 'hosts'; wildcard: boolean; hosts: string[]; exclude?: string[] }

export interface MenuCommand { script: string; scriptName: string; cmd: string; name: string; accessKey?: string; title?: string; autoClose?: boolean }
export interface MenuGrant { script: string; scriptName: string; host: string; patterns: string[] }
export interface MenuData { commands: MenuCommand[]; grants: MenuGrant[] }

export const T = { META: 0, HEAD: 1, DATA: 2, END: 3, ERROR: 4, CANCEL: 5 } as const;
