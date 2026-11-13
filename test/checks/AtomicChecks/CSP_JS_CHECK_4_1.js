const { session } = require("electron");

const cspPolicy = "default-src 'none'; script-src 'self'";
const extraHeaders = {
  "Content-Security-Policy": [cspPolicy]
};

session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      ...details.responseHeaders,
      ...extraHeaders
    }
  });
});
