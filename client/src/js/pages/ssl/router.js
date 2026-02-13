/* ==========================
    SSL TOOLS ROUTER
   ==========================
*/
import {
    setDisplay,
    resetUI
} from "../../utils/index.js";
// ===================================================
//  TOOL MENU BUTTONS (Sidebar / Toolbar)
// ===================================================
const toolMenuButtons = document.querySelectorAll(".js-tool-btn");
const btnToolChecker = document.getElementById("btnToolChecker");
const btnToolCsr = document.getElementById("btnToolCsr");
const btnToolCert = document.getElementById("btnToolCert");
const btnToolMatcher = document.getElementById("btnToolMatcher");
const btnToolConverter = document.getElementById("btnToolConverter");
// ===================================================
//  TOOL CONTAINERS (Tool Panels / Sections)
// ===================================================
const toolChecker = document.getElementById("toolChecker");
const toolCsr = document.getElementById("toolCsr");
const toolCert = document.getElementById("toolCert");
const toolMatcher = document.getElementById("toolMatcher");
const toolConverter = document.getElementById("toolConverter");
const toolResultChecker = document.getElementById("toolResultChecker");
const toolResult = document.getElementById("toolResult");
const toolShareLink = document.getElementById("toolShareLink");
const toolError = document.getElementById("toolError");

const RESET_SECTIONS = [
    toolResultChecker,
    toolResult,
    toolShareLink,
    toolError
];


// ===================================================
//  TOOL MENU + ROUTER HANDLERS
// ===================================================


/**
 * Map slug URL <=> Button + Panel
 */
const TOOL_ROUTE_MAP = {
    "ssl-checker": {
        btn: btnToolChecker,
        panel: toolChecker
    },
    "csr-decoder": {
        btn: btnToolCsr,
        panel: toolCsr
    },
    "cert-decoder": {
        btn: btnToolCert,
        panel: toolCert
    },
    "key-matcher": {
        btn: btnToolMatcher,
        panel: toolMatcher
    },
    "ssl-converter": {
        btn: btnToolConverter,
        panel: toolConverter
    }
};


/**
 * Lấy slug từ URL
 * /ssl-tools/csr-decoder => csr-decoder
 */
function getToolSlugFromURL() {
    const path = window.location.pathname;
    const parts = path.split("/").filter(Boolean);
    // ["ssl-tools", "csr-decoder"]
    return parts[1] || "ssl-checker";
}


/**
 * Active tool theo slug (có animation)
 */
function activateTool(slug, pushState = true) {

    /* ===== RESET GLOBAL RESULT UI ===== */

    if (slug !== currentSlug) {
        resetUI(RESET_SECTIONS);
    }


    if (!TOOL_ROUTE_MAP[slug]) {
        slug = "ssl-checker";
    }

    const config = TOOL_ROUTE_MAP[slug];


    /* ================= RESET BUTTON ================= */

    toolMenuButtons.forEach(btn => {
        btn.classList.remove("active");
    });


    /* ================= HIDE OLD PANELS ================= */

    Object.values(TOOL_ROUTE_MAP).forEach(item => {

        if (!item.panel) return;

        // Nếu là panel đang active thì bỏ qua
        if (item.panel === config.panel) return;

        // Fade out
        item.panel.classList.remove("ssl-tools__section--active");

        // Hide sau khi fade xong
        setTimeout(() => {

            setDisplay(item.panel, "none");

        }, 0);

    });


    /* ================= ACTIVE BUTTON ================= */

    if (config.btn) {
        config.btn.classList.add("active");
    }


    /* ================= SHOW NEW PANEL ================= */

    if (config.panel) {

        // Show trước
        setDisplay(config.panel, "block");

        // Force reflow
        config.panel.offsetHeight;

        // Fade in
        config.panel.classList.add("ssl-tools__section--active");
    }


    /* ================= UPDATE URL ================= */

    if (pushState) {

        let search = "";

        if (slug === "ssl-checker") {
            search = window.location.search;
        }

        const newUrl = `/ssl-tools/${slug}${search}`;

        history.pushState(
            { tool: slug },
            "",
            newUrl
        );
    }


}



/**
 * Bind click menu
 */
function bindToolMenuRouter() {
    Object.entries(TOOL_ROUTE_MAP).forEach(([slug, config]) => {
        if (!config.btn) return;
        config.btn.addEventListener("click", () => {
            activateTool(slug, true);
        });
    });
}

/**
 * Handle Back / Forward
 */
function handleBrowserNavigation() {
    window.addEventListener("popstate", e => {
        if (e.state && e.state.tool) {
            activateTool(e.state.tool, false);
        } else {
            const slug = getToolSlugFromURL();
            activateTool(slug, false);
        }
    });
}

// ==================================
// ===================================================
//  INITIALIZATION
// ===================================================

/**
 * Khởi tạo SSL Tools
 */
function initSSlTools() {
    // Bind menu
    bindToolMenuRouter();
    // Handle browser back/forward
    handleBrowserNavigation();
    // Active tool theo URL khi load
    const initSlug = getToolSlugFromURL();
    activateTool(initSlug, false);
}

// Run khi load page
document.addEventListener("DOMContentLoaded", initSSlTools);