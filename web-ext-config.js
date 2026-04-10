// web-ext configuration for pwledger
// See: https://extensionworkshop.com/documentation/develop/getting-started-with-web-ext/#setting-option-defaults-in-a-configuration-file
module.exports = {
  sourceDir: "./extension",
  artifactsDir: "./dist",
  ignoreFiles: [
    "pwledger.json",
    "pwledger-chrome.json",
  ],
  build: {
    overwriteDest: true,
  },
  run: {
    // Uncomment and set to your Firefox binary path for local testing:
    // firefox: "/usr/bin/firefox",
    startUrl: ["about:debugging#/runtime/this-firefox"],
    browserConsole: false,
  },
};
