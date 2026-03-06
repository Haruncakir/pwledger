// background.js
let port = null;

// Connect to the native messaging host
function connectNativeHost() {
    if (port) return;
    port = browser.runtime.connectNative("pwledger");

    port.onMessage.addListener((response) => {
        // Forward the response back to the sender (popup)
        // We match by message id
        if (response.id && pendingRequests[response.id]) {
            pendingRequests[response.id](response);
            delete pendingRequests[response.id];
        }
    });

    port.onDisconnect.addListener((p) => {
        if (p.error) {
            console.error(`Disconnected due to error: ${p.error.message}`);
        } else {
            console.log("Disconnected from native host");
        }
        port = null;
    });
}

const pendingRequests = {};
let messageIdCounter = 0;

// Listen for messages from the popup
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    connectNativeHost();

    const id = `${Date.now()}-${messageIdCounter++}`;
    const nativeMessage = { ...message, id };

    // Store the sendResponse function to call when the native host replies
    pendingRequests[id] = sendResponse;

    // Send the message to the native host
    port.postMessage(nativeMessage);

    // Return true to indicate we will send a response asynchronously
    return true;
});
