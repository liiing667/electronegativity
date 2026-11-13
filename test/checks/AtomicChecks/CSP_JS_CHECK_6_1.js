const { session } = require("electron");

const responseHeaders = {
  "Content-Security-Policy": ["default-src 'none'"]
};

session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  callback({ responseHeaders });
});
