const { session } = require("electron");

const cspPolicy = someConfig.csp || "default-src 'none'";
const dynamicName = getHeaderName();

session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({
    responseHeaders: {
      ...details.responseHeaders,
      [dynamicName]: [cspPolicy]
    }
  });
});
