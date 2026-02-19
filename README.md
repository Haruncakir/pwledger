# pwledger
- The Transient Clipboard:
  They give the OS the plaintext text, but strictly flag it as "Do not sync / Do not save to history," and then set a 10-second timer to wipe it.
- Browser Extension:
  To achieve this, you need to build a bridge between three separate components: your C++ application, a JSON manifest file that registers your app with the browser, and the browser extension itself.
