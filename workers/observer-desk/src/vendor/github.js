import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

var API = "https://api.github.com";
var DEFAULT_TIMEOUT_MS = 8e3;
var DEFAULT_MAX_JSON_BYTES = 2 * 1024 * 1024;
var COMMIT_SHA = /^[a-f0-9]{40}$/i;
var REPOSITORY = /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i;
var REF_NAME = /^[a-z0-9._/-]{1,200}$/i;
var RESERVED_ADDRESSES = new BlockList();
[
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4]
].forEach(([address, prefix]) => RESERVED_ADDRESSES.addSubnet(address, prefix, "ipv4"));
[
  ["::", 128],
  ["::1", 128],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
  ["2001:db8::", 32]
].forEach(([address, prefix]) => RESERVED_ADDRESSES.addSubnet(address, prefix, "ipv6"));
var ConnectorFetchError = class extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ConnectorFetchError";
    this.code = code;
  }
};
function timeoutSignal(timeoutMs = DEFAULT_TIMEOUT_MS) {
  return AbortSignal.timeout(Math.max(250, Number(timeoutMs) || DEFAULT_TIMEOUT_MS));
}
function responseMeta(response, provider) {
  return {
    provider,
    status: response.status,
    etag: response.headers.get("etag"),
    last_modified: response.headers.get("last-modified"),
    content_type: response.headers.get("content-type")
  };
}
async function boundedJson(response, maxBytes = DEFAULT_MAX_JSON_BYTES) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new ConnectorFetchError("payload_too_large", "Connector payload exceeds the permitted size");
  }
  const body = await response.text();
  if (Buffer.byteLength(body, "utf8") > maxBytes) {
    throw new ConnectorFetchError("payload_too_large", "Connector payload exceeds the permitted size");
  }
  try {
    return JSON.parse(body);
  } catch {
    throw new ConnectorFetchError("invalid_payload", "Connector response is not valid JSON");
  }
}
async function githubJsonWithMeta(repo, path, options = {}) {
  const token = options.token || process.env.GITHUB_READ_TOKEN || "";
  const ref = String(options.ref || "").trim();
  const repository = String(repo || "");
  const repositoryParts = repository.split("/");
  if (!REPOSITORY.test(repository) || repositoryParts.some((segment) => segment === "." || segment === "..")) {
    throw new ConnectorFetchError("invalid_endpoint", "GitHub repository is invalid");
  }
  if (!path || !/^[a-z0-9._/-]+$/i.test(String(path)) || String(path).startsWith("/") || String(path).split("/").some((segment) => !segment || segment === "." || segment === "..")) {
    throw new ConnectorFetchError("invalid_endpoint", "GitHub content path is invalid");
  }
  if (!COMMIT_SHA.test(ref)) throw new ConnectorFetchError("invalid_ref", "GitHub reads require a 40-character commit SHA");
  const url = new URL(`${API}/repos/${repo}/contents/${path}`);
  url.searchParams.set("ref", ref.toLowerCase());
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "malta-observer/1.3"
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(url, { headers, cache: "no-store", redirect: "manual", signal: timeoutSignal(options.timeoutMs) });
  if (!response.ok) throw new ConnectorFetchError(`http_${response.status}`, `GitHub HTTP ${response.status}`);
  const payload = await boundedJson(response, options.maxBytes);
  if (!payload?.content) throw new ConnectorFetchError("invalid_payload", "GitHub payload has no content");
  let data;
  try {
    const text = Buffer.from(payload.content, payload.encoding || "base64").toString("utf8");
    data = JSON.parse(text);
  } catch {
    throw new ConnectorFetchError("invalid_payload", "GitHub payload is not valid JSON");
  }
  return {
    data,
    meta: {
      ...responseMeta(response, "github"),
      repository: repo,
      path,
      ref: ref.toLowerCase(),
      content_sha: payload.sha || null
    }
  };
}
function validRepository(repository) {
  const value = String(repository || "");
  const parts = value.split("/");
  return REPOSITORY.test(value) && !parts.some((segment) => segment === "." || segment === "..");
}
function githubHeaders(token = "") {
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "malta-observer/1.3"
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}
async function githubResolveCommit(repo, ref, options = {}) {
  const repository = String(repo || "");
  const requestedRef = String(ref || "").trim();
  if (!validRepository(repository)) {
    throw new ConnectorFetchError("invalid_endpoint", "GitHub repository is invalid");
  }
  if (!REF_NAME.test(requestedRef) || requestedRef.startsWith("/") || requestedRef.endsWith("/") || requestedRef.split("/").some((segment) => !segment || segment === "." || segment === "..")) {
    throw new ConnectorFetchError("invalid_ref", "GitHub branch or tag is invalid");
  }
  const token = options.token || process.env.GITHUB_READ_TOKEN || "";
  const url = new URL(`${API}/repos/${repository}/commits/${encodeURIComponent(requestedRef)}`);
  const response = await fetch(url, {
    headers: githubHeaders(token),
    cache: "no-store",
    redirect: "manual",
    signal: timeoutSignal(options.timeoutMs)
  });
  if (!response.ok) throw new ConnectorFetchError(`http_${response.status}`, `GitHub HTTP ${response.status}`);
  const payload = await boundedJson(response, options.maxBytes || 512 * 1024);
  const commit = String(payload?.sha || "").toLowerCase();
  if (!COMMIT_SHA.test(commit)) throw new ConnectorFetchError("invalid_payload", "GitHub commit response has no immutable SHA");
  return {
    commit,
    requested_ref: requestedRef,
    committed_at: payload?.commit?.committer?.date || payload?.commit?.author?.date || null,
    meta: { ...responseMeta(response, "github"), repository, ref: requestedRef }
  };
}
async function githubTreeWithMeta(repo, commit, options = {}) {
  const repository = String(repo || "");
  const immutableCommit = String(commit || "").trim().toLowerCase();
  if (!validRepository(repository)) {
    throw new ConnectorFetchError("invalid_endpoint", "GitHub repository is invalid");
  }
  if (!COMMIT_SHA.test(immutableCommit)) {
    throw new ConnectorFetchError("invalid_ref", "GitHub tree reads require a 40-character commit SHA");
  }
  const token = options.token || process.env.GITHUB_READ_TOKEN || "";
  const url = new URL(`${API}/repos/${repository}/git/trees/${immutableCommit}`);
  url.searchParams.set("recursive", "1");
  const response = await fetch(url, {
    headers: githubHeaders(token),
    cache: "no-store",
    redirect: "manual",
    signal: timeoutSignal(options.timeoutMs)
  });
  if (!response.ok) throw new ConnectorFetchError(`http_${response.status}`, `GitHub HTTP ${response.status}`);
  const data = await boundedJson(response, options.maxBytes || 3 * 1024 * 1024);
  if (!Array.isArray(data?.tree)) throw new ConnectorFetchError("invalid_payload", "GitHub tree response is invalid");
  return {
    data,
    meta: { ...responseMeta(response, "github"), repository, ref: immutableCommit }
  };
}

export { githubJsonWithMeta, githubResolveCommit, githubTreeWithMeta };
