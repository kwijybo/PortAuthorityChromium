
export async function notifyPortScanning(domain_name) {
    const message = (domain_name) ?
        "Port Authority blocked " + domain_name + " from port scanning your private network."
        : "Port Authority blocked this site from port scanning your private network.";

    return chrome.notifications.create("port-scanning-notification", {
        "type": "basic",
        "iconUrl": chrome.runtime.getURL("icons/logo-96.png"),
        "title": "Port Scan Blocked",
        "message": message
    });
}

export async function notifyThreatMetrix(domain_name) {
    const message = (domain_name) ?
        "Port Authority blocked a hidden LexisNexis endpoint on " + domain_name + " from running an invasive data collection script."
        : "Port Authority blocked a hidden LexisNexis endpoint from running an invasive data collection script.";

    return chrome.notifications.create("threatmetrix-notification", {
        "type": "basic",
        "iconUrl": chrome.runtime.getURL("icons/logo-96.png"),
        "title": "Tracking Script Blocked",
        "message": message
    });
}


/**
 * Updates the extension button's little badge text, only on the tab where it's relevant.
 * Note: when displayActionCountAsBadgeText is enabled in the background, Chrome's built-in
 * rule-match counter overrides any text set here.
 * @param {string} text The new badge text to display
 * @param {number} tabId The id of the tab to show the new badge on
 */
export function updateBadges(text, tabId) {
    try {
        chrome.action.setBadgeText({
            text: text.toString(),
            tabId: parseInt(tabId)
        });
    } catch (error) {
        console.error("Couldn't update badge:", { tabId, text, error });
    }
}


/**
 * Call from a scope which has access to `chrome.tabs`
 * @returns {Promise<number>} The id number of the focused tab
*/
export async function getActiveTabId() {
    const querying = await chrome.tabs.query({
        currentWindow: true,
        active: true,
    });
    const tab = querying[0];
    return tab.id;
}
