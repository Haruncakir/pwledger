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

// Send a command to the native host and return a Promise for the response.
function sendNativeCommand(message) {
    return new Promise((resolve) => {
        connectNativeHost();
        const id = `${Date.now()}-${messageIdCounter++}`;
        const nativeMessage = { ...message, id };
        pendingRequests[id] = resolve;
        port.postMessage(nativeMessage);
    });
}

// Listen for messages from the popup AND content scripts
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {

    // -----------------------------------------------------------------------
    // Content script: page loaded — check for matching credentials
    // -----------------------------------------------------------------------
    if (message.command === "page_loaded") {
        (async () => {
            try {
                // Extract hostname from the URL
                let hostname = "";
                try {
                    hostname = new URL(message.url).hostname;
                } catch (_) {
                    sendResponse({ status: "error", message: "Invalid URL" });
                    return;
                }

                // Ask the native host for entries matching this hostname
                const searchResponse = await sendNativeCommand({
                    command: "search",
                    query: hostname,
                });

                if (searchResponse && searchResponse.status === "ok") {
                    sendResponse({
                        status: "ok",
                        results: searchResponse.results || [],
                    });
                } else {
                    sendResponse({
                        status: "error",
                        message: searchResponse?.message || "Search failed",
                    });
                }
            } catch (e) {
                sendResponse({ status: "error", message: "Communication error" });
            }
        })();
        return true; // async response
    }

    // -----------------------------------------------------------------------
    // Content script or popup: fill credentials (get username + password)
    // -----------------------------------------------------------------------
    if (message.command === "fill_credentials") {
        (async () => {
            try {
                const credsResponse = await sendNativeCommand({
                    command: "get_credentials",
                    uuid: message.uuid,
                });

                if (credsResponse && credsResponse.status === "ok") {
                    // If request came from popup, forward to the active tab's
                    // content script instead of responding directly.
                    if (message.from_popup) {
                        const tabs = await browser.tabs.query({
                            active: true,
                            currentWindow: true,
                        });
                        if (tabs.length > 0) {
                            browser.tabs.sendMessage(tabs[0].id, {
                                command: "do_fill",
                                username: credsResponse.username,
                                password: credsResponse.password,
                            });
                        }
                        sendResponse({ status: "ok" });
                    } else {
                        sendResponse({
                            status: "ok",
                            username: credsResponse.username,
                            password: credsResponse.password,
                        });
                    }
                } else {
                    sendResponse({
                        status: "error",
                        message: credsResponse?.message || "Failed to get credentials",
                    });
                }
            } catch (e) {
                sendResponse({ status: "error", message: "Communication error" });
            }
        })();
        return true; // async response
    }

    // -----------------------------------------------------------------------
    // All other commands from the popup (unlock, lock, search, copy, etc.)
    // -----------------------------------------------------------------------
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
