import { getItemFromLocal, setItemInLocal, modifyItemInLocal,
    addBlockedPortToHost, addBlockedTrackingHost, increaseBadge } from "./global/BrowserStorageManager.js";

// Rule IDs for the dynamic declarativeNetRequest blocking rules
const RULE_IDS = Object.freeze({
    LOOPBACK:       1,  // 127.x.x.x
    NULL_IP:        2,  // 0.0.0.0
    CLASS_A:        3,  // 10.x.x.x
    LOCALHOST:      4,  // localhost
    CLASS_B_172:    5,  // 172.16–31.x.x
    CLASS_C:        6,  // 192.168.x.x
    LINK_LOCAL:     7,  // 169.254.x.x
    THREATMETRIX:   8,  // *.online-metrix.net
});

/**
 * Build the full set of blocking rules, injecting the current allowlist as
 * `excludedInitiatorDomains` so those origins are never blocked.
 *
 * @param {string[]} allowed_domains Hostnames that should bypass blocking
 * @returns {chrome.declarativeNetRequest.Rule[]}
 */
function buildRules(allowed_domains = []) {
    // declarativeNetRequest rejects an empty excludedInitiatorDomains array
    const excluded = allowed_domains.length > 0
        ? { excludedInitiatorDomains: allowed_domains }
        : {};

    const thirdPartyBase = {
        domainType: "thirdParty",
        isUrlFilterCaseSensitive: false,
        ...excluded,
    };

    return [
        {   // 127.x.x.x  (loopback)
            id: RULE_IDS.LOOPBACK, priority: 1,
            action: { type: "block" },
            condition: { ...thirdPartyBase, regexFilter: "^[^:]+://127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(/|:|$)" }
        },
        {   // 0.0.0.0
            id: RULE_IDS.NULL_IP, priority: 1,
            action: { type: "block" },
            condition: { ...thirdPartyBase, regexFilter: "^[^:]+://0\\.0\\.0\\.0(/|:|$)" }
        },
        {   // 10.x.x.x  (RFC-1918 class A)
            id: RULE_IDS.CLASS_A, priority: 1,
            action: { type: "block" },
            condition: { ...thirdPartyBase, regexFilter: "^[^:]+://10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(/|:|$)" }
        },
        {   // localhost
            id: RULE_IDS.LOCALHOST, priority: 1,
            action: { type: "block" },
            condition: { ...thirdPartyBase, regexFilter: "^[^:]+://localhost(/|:|$)" }
        },
        {   // 172.16–31.x.x  (RFC-1918 class B)
            id: RULE_IDS.CLASS_B_172, priority: 1,
            action: { type: "block" },
            condition: { ...thirdPartyBase, regexFilter: "^[^:]+://172\\.(1[6-9]|2[0-9]|3[01])\\.\\d{1,3}\\.\\d{1,3}(/|:|$)" }
        },
        {   // 192.168.x.x  (RFC-1918 class C)
            id: RULE_IDS.CLASS_C, priority: 1,
            action: { type: "block" },
            condition: { ...thirdPartyBase, regexFilter: "^[^:]+://192\\.168\\.\\d{1,3}\\.\\d{1,3}(/|:|$)" }
        },
        {   // 169.254.x.x  (link-local / APIPA)
            id: RULE_IDS.LINK_LOCAL, priority: 1,
            action: { type: "block" },
            condition: { ...thirdPartyBase, regexFilter: "^[^:]+://169\\.254\\.\\d{1,3}\\.\\d{1,3}(/|:|$)" }
        },
        {   // *.online-metrix.net  (ThreatMetrix / LexisNexis)
            // Replaces the Firefox-only browser.dns.resolve() CNAME check
            id: RULE_IDS.THREATMETRIX, priority: 1,
            action: { type: "block" },
            condition: {
                ...thirdPartyBase,
                requestDomains: ["online-metrix.net"],
            }
        },
    ];
}

async function startup() {
    console.log("Startup called");

    // Use Chrome's built-in per-tab rule-match counter as the badge text.
    // This replaces the manual badge updates that relied on webRequest callbacks.
    await chrome.declarativeNetRequest.setExtensionActionOptions({
        displayActionCountAsBadgeText: true,
    });

    // Get the blocking state from cold storage
    const state = await getItemFromLocal("blocking_enabled", true);
    if (state === true) {
        await start();
    } else {
        await stop();
    }
}

async function start() {  // Enables blocking
    try {
        const allowed_domains = await getItemFromLocal("allowed_domain_list", []);
        const rules = buildRules(allowed_domains);

        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: Object.values(RULE_IDS),
            addRules: rules,
        });

        console.log("Dynamic blocking rules added: blocking enabled");
        await setItemInLocal("blocking_enabled", true);
    } catch (e) {
        console.error("START() ", e);
    }
}

async function stop() {  // Disables blocking
    try {
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: Object.values(RULE_IDS),
        });

        console.log("Dynamic blocking rules removed: blocking disabled");
        await setItemInLocal("blocking_enabled", false);
    } catch (e) {
        console.error("STOP() ", e);
    }
}

async function isListening() {  // Returns true when blocking rules are active
    // Storage is always updated in sync with rule additions/removals by start()/stop(),
    // so it is the reliable source of truth without needing to enumerate dynamic rules.
    return getItemFromLocal("blocking_enabled", true);
}

/**
 * Called by each tab update.
 * Clears per-tab blocked-port and blocked-host data when the tab navigates.
 * Borrowed and modified from https://gitlab.com/KevinRoebert/ClearUrls/-/blob/master/core_js/badgedHandler.js
 */
async function handleUpdated(tabId, changeInfo, tabInfo) {
    // TODO investigate a better way to interact with current locking practices
    const badges = await getItemFromLocal("badges", {});
    if (!badges[tabId] || !changeInfo.url) return;

    if (badges[tabId].lastURL !== changeInfo.url) {
        badges[tabId] = {
            counter: 0,
            alerted: 0,
            lastURL: tabInfo.url
        };
        await setItemInLocal("badges", badges);

        // Clear out the blocked ports for the current tab
        await modifyItemInLocal("blocked_ports", {},
            (blocked_ports_object) => {
                delete blocked_ports_object[tabId];
                return blocked_ports_object;
            });

        // Clear out the hosts for the current tab
        await modifyItemInLocal("blocked_hosts", {},
            (blocked_hosts_object) => {
                delete blocked_hosts_object[tabId];
                return blocked_hosts_object;
            });
    }
}

const extensionOrigin = new URL(chrome.runtime.getURL("")).origin;
async function onMessage(message, sender) {
    if (sender.origin !== extensionOrigin) {
        console.warn('Message from unexpected origin:', sender.url);
        return;
    }

    switch (message.type) {
        case 'toggleEnabled':
            message.value ? await start() : await stop();
            break;
        default:
            console.warn('Port Authority: unknown message: ', message);
            break;
    }
}
chrome.runtime.onMessage.addListener(onMessage);

// When the allowed_domain_list changes (e.g. from the settings page), rebuild
// the blocking rules so the new allowlist is reflected immediately.
chrome.storage.onChanged.addListener(async (changes, area) => {
    if (area !== 'local' || !changes['allowed_domain_list']) return;
    const blocking_enabled = await getItemFromLocal("blocking_enabled", true);
    if (blocking_enabled) {
        await start();
    }
});

// onRuleMatchedDebug is only available for unpacked (developer-mode) extensions.
// It fires whenever a declarativeNetRequest rule matches a request and allows us
// to populate the popup's blocked-ports / blocked-hosts lists and show notifications.
// NOTE: In a packed (production) extension this listener is absent; blocking still
// works via declarativeNetRequest, and the badge is auto-updated by Chrome's built-in
// rule-match counter (setExtensionActionOptions above), but the detailed popup list
// and first-block notifications will be unavailable.
if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
    chrome.declarativeNetRequest.onRuleMatchedDebug.addListener(
        async ({ request, rule }) => {
            if (!request || request.tabId === -1) return;

            const isThreatMetrix = rule.ruleId === RULE_IDS.THREATMETRIX;
            let url;
            try {
                url = new URL(request.url);
            } catch (e) {
                console.error("Error parsing blocked request URL:", request.url, e);
                return;
            }

            // increaseBadge handles per-tab first-block notification logic and
            // storage tracking. The badge TEXT itself is auto-managed by Chrome's
            // rule-match counter (chrome.action.setBadgeText calls are overridden).
            await increaseBadge(request, isThreatMetrix);
            if (isThreatMetrix) {
                await addBlockedTrackingHost(url, request.tabId);
            } else {
                await addBlockedPortToHost(url, request.tabId);
            }
        }
    );
}

startup();
// Call by each tab is updated.
chrome.tabs.onUpdated.addListener(handleUpdated);
