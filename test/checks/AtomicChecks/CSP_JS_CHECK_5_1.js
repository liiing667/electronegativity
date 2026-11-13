const { session } = require("electron");

const cspHeaderName = "content-security-policy";
const cspPolicy = "default-src 'self'";

session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  details.responseHeaders[cspHeaderName] = [cspPolicy];
  callback(details);
});
