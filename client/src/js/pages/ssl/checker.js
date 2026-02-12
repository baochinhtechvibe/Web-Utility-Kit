// ===================================================
//  SSL TOOLS - SSL CHECKER PAGE
// ===================================================
import {
    /* dom.js */
    toggleLoading,
    show,
    hide,
    setDisplay,
    showElements,
    resetUI,
    showError,

    /* network.js */
    normalizeHostnameInput,

    /* url.js */
    getWhoisDomain,
    setupCopyButton,

    /* format.js */
    formatDate
} from "../../utils/index.js";

// ===================================================
//  CONFIGURATION
// ===================================================

/*
 * Base URL của Backend API
 */
const API_BASE_URL = "http://localhost:3102/api";

/*
 * SSL Checker Elements
 */
const btnToolChecker = document.getElementById("btnToolChecker");
const toolChecker = document.getElementById("toolChecker")
const formChecker = document.getElementById("formChecker");
const inputChecker = document.getElementById("inputChecker");
const btnSubmitChecker = document.getElementById("btnSubmitChecker");
const iconCheckerArrow = document.getElementById("iconCheckerArrow");
const iconCheckerLoading = document.getElementById("iconCheckerLoading");
const toolResultChecker = document.getElementById("toolResultChecker");
const resultCheckerHeader = document.getElementById("resultCheckerHeader");
const resultDomainName = document.getElementById("resultDomainName");
const btnWhoisChecker = document.getElementById("btnWhoisChecker");
const resultCheckerContent = document.getElementById("resultCheckerContent");
const toolShareLink = document.getElementById("toolShareLink");
const shareLinkChecker = document.getElementById("shareLinkChecker");
const btnCopyLinkChecker = document.getElementById("btnCopyLinkChecker");
const toolError = document.getElementById("toolError");
const toolErrorTitle = document.getElementById("toolErrorTitle");
const toolErrorMessage = document.getElementById("toolErrorMessage");

const safe = (v, fallback = "N/A") => (v === null || v === undefined || v === "" ? fallback : v);

const issuerLogoMap = {
    "DigiCert": "digicert.svg",
    "Let's Encrypt": "letsencrypt.svg",
    "ZeroSSL": "zerossl.svg",
    "Sectigo": "sectigo.svg",
    "GlobalSign": "globalsign.svg",
    "Amazon": "amazon.svg",
    "Cloudflare": "cloudflare.svg",
    "GoDaddy": "godaddy.svg",
};

const SSL_EXPIRY_THRESHOLDS = {
    EXPIRED: 0,   // < 0 days = expired
    WARNING: 30,   // < 30 days = warning
};

const CERT_CHAIN_CONFIG = {
    BASE_PATH: '/client/public/assets/images/tools/ssl/cert_chain/',

    LEVEL_MAP: {
        domain: 'DOMAIN',
        intermediate: 'CA',
        root: 'CA'
    },

    ICONS: {
        DOMAIN: {
            VALID: { src: 'certificate_good_server.png', alt: 'Valid Domain Certificate' },
            EXPIRED: { src: 'certificate_bad_server.png', alt: 'Expired Domain Certificate' }
        },

        CA: {
            VALID: { src: 'certificate_good_chain.png', alt: 'Valid CA Certificate' },
            EXPIRED: { src: 'certificate_bad_chain.png', alt: 'Expired CA Certificate' }
        }
    }
};

const issuerBrandCache = new Map();

/* =================================
    HELPER UTILS FUNCTIONS
================================== */

function escapeHTML(str = "") {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

/**
 * @param {number} n
 * @returns {string}
 */
function formatDays(n) {
    if (typeof n !== "number") {
        return "N/A";
    }
    if (n >= 0) {
        return `${n} ngày`;
    }
    return `${Math.abs(n)} ngày trước`;
}


function renderFatalError(msg) {

    btnWhoisChecker.onclick = null;

    setDisplay(resultCheckerHeader, "none");
    setDisplay(toolError, "block");

    showError(
        toolError,
        toolErrorMessage,
        msg,
        [resultCheckerContent, toolShareLink]
    );
}

/* =================================
    HELPER RENDER UI FUNCTIONS
================================== */

/**
 * Xác định trạng thái badge tổng quan của SSL
 *
 * Dựa trên:
 * - Mức độ tin cậy (trusted)
 * - Số ngày còn lại của chứng chỉ (day_left)
 *
 * Quy ước:
 *  - ok       : trusted = true && days >= WARNING
 *  - warning  : trusted = true && 0 < days < WARNING
 *  - critical : trusted = false || days < 0
 *
 * @param {boolean} trusted - Chứng chỉ có được tin cậy hay không
 * @param {number} day_left - Số ngày còn lại của chứng chỉ
 *
 * @returns {"ok" | "warning" | "critical"} badge status
 */
function getBadgeStatus(trusted, day_left) {

    const isTrusted = Boolean(trusted);
    const days = Number(day_left);

    // Days không hợp lệ → coi như critical
    if (!Number.isFinite(days)) {
        return "critical";
    }

    // Không trusted hoặc đã hết hạn
    if (!isTrusted || days < SSL_EXPIRY_THRESHOLDS.EXPIRED) {
        return "critical";
    }

    // Sắp hết hạn
    if (days < SSL_EXPIRY_THRESHOLDS.WARNING) {
        return "warning";
    }

    // Còn hạn + trusted
    return "valid";
}


/* Render hostname_ok */
/**
 * Trả về thông điệp và đặt tên Class theo giá trị trả về của hostname_ok
 *
 * @param {boolean} hostname_ok
 * @param {string} hostname
 * @returns {{
 *  message: string
 *  iconClass: string
 * }}
 */
function getHostnameStatus(hostname_ok, hostname) {
    if (hostname_ok) {
        return {
            message: `Hostname (${escapeHTML(safe(hostname))}) khớp trong chứng chỉ.`,
            iconClass: "ok"
        };
    }

    return {
        message: "",
        iconClass: "false"
    };
}

/**
 * Phân loại TLS version và trả về message + class hiển thị
 *
 * iconClass dùng cho UI:
 *  - good      : TLS 1.3 (rất tốt)
 *  - ok        : TLS 1.2 (ổn)
 *  - weak      : TLS 1.1 (yếu)
 *  - bad       : TLS 1.0 (kém)
 *  - insecure  : SSL (không an toàn)
 *  - unknown   : Không xác định
 *
 * @param {string|null} tlsVersion - Ví dụ: "TLS 1.3", "TLS 1.2"
 * @returns {{ message: string, iconClass: string }}
 */
function getTSLInfo(tlsVersion) {

    // Không có dữ liệu
    if (typeof tlsVersion !== "string" || !tlsVersion.trim()) {
        return {
            message: "",
            iconClass: "unknown"
        };
    }

    // Chuẩn hóa
    const version = tlsVersion.trim();
    const v = version.toUpperCase();

    let iconClass = "unknown";

    if (v === "TLS 1.3") {
        iconClass = "good";

    } else if (v === "TLS 1.2") {
        iconClass = "ok";

    } else if (v === "TLS 1.1") {
        iconClass = "weak";

    } else if (v === "TLS 1.0") {
        iconClass = "bad";

    } else if (v.startsWith("SSL")) {
        iconClass = "insecure";
    }

    return {
        message: version,
        iconClass
    };
}


/* Render Issuer */
/**
 * Tạo mô tả văn bản về CA phát hành chứng chỉ
 *
 * @param {string} issuerBrand
 * @returns {string}
 */
function getIssuerStatus(issuerBrand) {

    if (!issuerBrand) {
        return "";
    }

    return `<span>Chứng chỉ được phát hành bởi&nbsp;<strong class="result-checker__message--value result-checker__message--issuer mr-4"> ${issuerBrand}.</strong></span>`;
}

/**
 * Xác định thương hiệu CA từ chuỗi issuer của certificate
 *
 * @param {Array} cert_chain
 * @returns {string} Tên CA (hoặc chuỗi rỗng nếu không xác định)
 */
function getIssuerBrand(cert_chain) {

    const issuer = (cert_chain?.[0]?.issuer || "");

    if (issuerBrandCache.has(issuer)) {
        return issuerBrandCache.get(issuer);
    }

    const lower = issuer.toLowerCase();
    let result = "";

    if (lower.includes("digicert")) result = "DigiCert";
    else if (lower.includes("let's encrypt") || lower.includes("lets encrypt")) result = "Let's Encrypt";
    else if (lower.includes("sectigo") || lower.includes("comodoca") || lower.includes("comodo")) result = "Sectigo";
    else if (lower.includes("globalsign")) result = "GlobalSign";
    else if (lower.includes("geotrust")) result = "GeoTrust";
    else if (lower.includes("entrust")) result = "Entrust";
    else if (lower.includes("zerossl")) result = "ZeroSSL";

    issuerBrandCache.set(issuer, result);

    return result;
}

/**
 * Lấy đường dẫn logo của CA dựa trên brand
 *
 * @param {string} issuerBrand
 * @param {Object} issuerLogoMap
 * @returns {string}
 */
function getIssuerLogoPath(issuerBrand, issuerLogoMap) {

    if (
        issuerBrand &&
        issuerLogoMap &&
        issuerLogoMap[issuerBrand]
    ) {
        return `/client/public/assets/images/tools/ssl/ca/${issuerLogoMap[issuerBrand]}`;
    }

    return "";
}

/**
 * Render HTML logo CA
 *
 * @param {string} issuerBrand
 * @param {string} issuerLogoPath
 * @returns {string}
 */
function renderIssuerLogoHTML(issuerBrand, issuerLogoPath) {

    if (!issuerLogoPath) {
        return "";
    }

    return `
        <img
            src="${issuerLogoPath}"
            alt="${issuerBrand} logo"
            width="72px"
            height="72px"
            loading="lazy"
        />
    `;
}

/* Render trusted */

/**
 * Trả về thông điệp và đặt tên Class theo giá trị trả về của Trusted
 *
 * @param {boolean} trusted
 * @returns {{
 *  message: string
 *  iconClass: string
 * }}
 */
function getTrustedStatus(trusted) {
    if (trusted) {
        return {
            message: `Chứng chỉ được tin cậy bởi hầu hết trình duyệt. (Tất cả các chứng chỉ trung gian cần thiết đã được cài đặt).`,
            iconClass: "ok"
        };
    }

    return {
        message: "",
        iconClass: "false"
    };
}

/**
 * Render danh sách trust issue (nếu có)
 *
 * @param {Array} trust_issue
 * @returns {string} HTML
 */
function renderTrustIssues(trust_issue) {

    if (!Array.isArray(trust_issue)) return "";

    return trust_issue.map(issue => {

        let extra = "";

        if (issue.code === "cert_expired") {
            extra = `
                <a href="https://tino.vn/chung-chi-bao-mat-ssl?php=4842" target="_blank" rel="noopener noreferrer" class="btnRenewSSL">
                    Renew
                </a>
            `;
        }

        return `
            <tr>
                <td class="result-checker__icon result-checker__icon--trusted-issue">&nbsp;</td>
                <td>
                    <strong class="result-checker__message-trust-issues ${issue.code.toLowerCase()}">
                        ${escapeHTML(issue.message || "")}
                        ${extra}
                    </strong>
                </td>
            </tr>
        `;
    }).join("");
}


/**
 * Chuẩn hóa dữ liệu trust state từ API / backend
 *
 * Mục đích:
 * - Trích xuất các cờ quan trọng liên quan đến SSL
 * - Xác định có issue về trust hay không
 * - Trả về object gọn nhẹ để xử lý logic phía sau
 *
 * @param {Object} data
 * @param {boolean} data.hostname_ok - Hostname có khớp chứng chỉ hay không
 * @param {boolean} data.trusted - Chứng chỉ có được tin cậy hay không
 * @param {Array} data.trust_issue - Danh sách lỗi / cảnh báo về trust
 *
 * @returns {{
 *   hostname_ok: boolean,
 *   trusted: boolean,
 *   hasIssue: boolean
 * }}
 */
function getTrustState(data) {

    const {
        hostname_ok,
        trusted,
        trust_issue
    } = data;

    // Có issue nếu trust_issue là mảng và có phần tử
    const hasIssue =
        Array.isArray(trust_issue) && trust_issue.length > 0;

    return {
        hostname_ok,
        trusted,
        hasIssue,
    };
}

/**
 * Xác định case logic SSL dựa trên trust state
 *
 * Các case được phân loại:
 *
 * PERFECT:
 *  - Hostname đúng
 *  - Chứng chỉ tin cậy
 *  - Không có issue
 *
 * MINOR_ISSUE:
 *  - Hostname đúng
 *  - Chứng chỉ tin cậy
 *  - Có issue nhẹ (ví dụ chain, warning)
 *
 * UNTRUSTED:
 *  - Hostname đúng
 *  - Chứng chỉ không tin cậy
 *
 * BROKEN:
 *  - Hostname sai
 *  - Chứng chỉ không tin cậy
 *
 * WEIRD / WEIRD_WITH_ISSUE (hiếm):
 *  - Hostname sai nhưng chứng chỉ lại trusted
 *
 * @param {{
 *   hostname_ok: boolean,
 *   trusted: boolean,
 *   hasIssue: boolean
 * }} state
 *
 * @returns {string} case type
 */
function detectCase(state) {

    const { hostname_ok, trusted, hasIssue } = state;

    // TH1: Hoàn hảo
    if (hostname_ok && trusted && !hasIssue) {
        return "PERFECT";
    }

    // TH2: Tin cậy nhưng có issue nhẹ
    if (hostname_ok && trusted && hasIssue) {
        return "MINOR_ISSUE";
    }

    // TH3: Hostname đúng nhưng chứng chỉ không tin cậy
    if (hostname_ok && !trusted) {
        return "UNTRUSTED";
    }

    // TH4: Hostname sai + chứng chỉ không tin cậy
    if (!hostname_ok && !trusted) {
        return "BROKEN";
    }

    // TH5: Trường hợp bất thường
    if (!hostname_ok && trusted && !hasIssue) {
        return "WEIRD";
    }

    // TH6: Bất thường + có issue
    if (!hostname_ok && trusted && hasIssue) {
        return "WEIRD_WITH_ISSUE";
    }

    // Không khớp bất kỳ case nào
    return "UNKNOWN";
}


/**
 * Render UI tương ứng với từng case SSL
 *
 * Mỗi case sẽ map tới một hàm render riêng
 * để dễ quản lý và mở rộng UI sau này
 *
 * @param {string} caseType - Kết quả từ detectCase()
 * @param {Object} data - Dữ liệu gốc dùng để render
 *
 * @returns {string} HTML
 */
function renderByCase(caseType, data) {

    switch (caseType) {

        case "PERFECT":
            return renderPerfect(data);

        case "MINOR_ISSUE":
            return renderMinorIssue(data);

        case "UNTRUSTED":
            return renderUntrusted(data);

        case "BROKEN":
            return renderBroken(data);

        case "WEIRD":
            return renderWeird(data);

        case "WEIRD_WITH_ISSUE":
            return renderWeirdWithIssue(data);

        default:
            return `<p>Không xác định trạng thái SSL.</p>`;
    }
}

/**
 * Render một dòng hiển thị thông tin ngày hết hạn SSL
 *
 * - Chỉ render khi expiry.visible = true
 * - Hiển thị icon + nội dung trạng thái hết hạn
 *
 * @param {Object} expiry - Kết quả từ getExpiryInfo()
 * @returns {string} HTML <tr> hoặc chuỗi rỗng
*/
function renderExpiryRow(expiry) {

    if (!expiry.visible) return "";

    return `
        <tr>
            <td class="result-checker__icon result-checker__icon--expiryDay-${expiry.iconClass}">&nbsp;</td>
            <td>
                <span class="result-checker__message">${expiry.html}</span>
            </td>
        </tr>
    `;
}

/**
 * Tạo thông tin trạng thái hết hạn SSL để render UI
 *
 * Status:
 * - ok      : > 30 ngày
 * - warning : ≤ 30 ngày
 * - expired : hết hạn / không hợp lệ
 *
 * @param {boolean} valid
 * @param {number} days_left
 * @returns {{
 *   status: "ok" | "warning" | "expired",
 *   html: string,
 *   iconClass: string,
 *   wrapperClass: string,
 *   visible: boolean
 * }}
 */

function getExpiryInfo(valid, days_left) {
    const isValid = Boolean(valid);
    const days = Number(days_left);

    // Kiểm tra days có phải số hợp lệ không
    const isDaysValid = Number.isFinite(days);

    let status = "ok";

    if (!isValid || !isDaysValid || days <= SSL_EXPIRY_THRESHOLDS.EXPIRED) {
        status = "expired";
    } else if (!Number.isNaN(days) && days < SSL_EXPIRY_THRESHOLDS.WARNING) {
        status = "warning";
    }

    const config = {
        ok: {
            iconClass: "ok",
            wrapperClass: "ssl-tool__chain-day-left-ok",
            label: "Chứng chỉ sẽ hết hạn sau",
            valueClass: "result-checker__message result-checker__message--expiry ok",
        },

        warning: {
            iconClass: "warning",
            wrapperClass: "ssl-tool__chain-day-left-warning",
            label: "Chứng chỉ sẽ hết hạn sau",
            valueClass: "result-checker__message result-checker__message--expiry warning",
        },

        expired: {
            iconClass: "critical",
            wrapperClass: "ssl-tool__chain-day-left-critical",
            label: "Chứng chỉ đã hết hạn",
            valueClass: "result-checker__message result-checker__message--expiry critical",
        },
    };

    const cfg = config[status];

    const html = `
        ${cfg.label}
        <strong class="${cfg.valueClass}">${formatDays(days)}</strong>.
    `;

    return {
        status,
        html,
        iconClass: cfg.iconClass,
        wrapperClass: cfg.wrapperClass,

        // Có hiển thị không
        visible: isValid && isDaysValid && days > 0,
    };
}

/* =========================
    CASE RENDER FUNCTIONS
========================== */
/**
 * Render UI cho case PERFECT
 *
 * Điều kiện:
 * - Hostname đúng
 * - Chứng chỉ được tin cậy
 * - Không có issue
 *
 * Hiển thị:
 * - Trạng thái trusted
 * - Thông tin ngày hết hạn
 * - Trạng thái hostname (nếu có)
 *
 * @param {Object} data - Dữ liệu SSL từ backend
 * @returns {string} HTML
 */
function renderPerfect(data) {
    const {
        hostname,
        hostname_ok,
        valid,
        days_left,
        trusted,
    } = data;

    const hostnameOk = getHostnameStatus(hostname_ok, hostname);
    const trustedInfo = getTrustedStatus(trusted);
    const expiry = getExpiryInfo(valid, days_left);

    return `
        <tr>
            <td class = "result-checker__icon result-checker__icon--trusted-${trustedInfo.iconClass}">&nbsp;</td>
            <td>
                <strong class="result-checker__message result-checker__message-trustedMessage">
                    ${trustedInfo.message}
                </strong>
            </td>
        </tr>
        ${renderExpiryRow(expiry)}
        ${hostnameOk.message ? `
        <tr>
            <td class = "result-checker__icon result-checker__icon--hostname${hostnameOk.iconClass}">&nbsp;</td>
            <td >
                <strong class="result-checker__message result-checker__message--hostnameStatus">
                    ${hostnameOk.message}
                </strong>
            </td>
        </tr>` : ""}
    `;
}

function renderMinorIssue(data) {

}

/**
 * Render UI cho case UNTRUSTED
 *
 * Điều kiện:
 * - Hostname đúng
 * - Chứng chỉ không được tin cậy
 *
 * Hiển thị:
 * - Thông tin ngày hết hạn
 * - Trạng thái hostname (nếu có)
 * - Danh sách lỗi trust
 *
 * @param {Object} data - Dữ liệu SSL từ backend
 * @returns {string} HTML
 */
function renderUntrusted(data) {
    const {
        hostname,
        hostname_ok,
        valid,
        days_left,
        trust_issue,
    } = data;
    const hostnameOk = getHostnameStatus(hostname_ok, hostname);
    const listTrustIssues = renderTrustIssues(trust_issue);
    const expiry = getExpiryInfo(valid, days_left);

    return `
        ${renderExpiryRow(expiry)}
        ${hostnameOk.message ? `
        <tr>
            <td class = "result-checker__icon result-checker__icon--hostname${hostnameOk.iconClass}">&nbsp;</td>
            <td >
                <strong class="result-checker__message result-checker__message-hostnameStatus">
                    ${hostnameOk.message}
                </strong>
            </td>
        </tr>` : ""}
        ${listTrustIssues}
    `;
}

/**
 * Render UI cho case BROKEN
 *
 * Điều kiện:
 * - Hostname sai
 * - Chứng chỉ không được tin cậy
 *
 * Hiển thị:
 * - Thông tin ngày hết hạn
 * - Danh sách lỗi trust
 *
 * @param {Object} data - Dữ liệu SSL từ backend
 * @returns {string} HTML
 */
function renderBroken(data) {
    const {
        valid,
        days_left,
        trust_issue,
    } = data;
    const listTrustIssues = renderTrustIssues(trust_issue);

    const expiry = getExpiryInfo(valid, days_left);

    return `
        ${renderExpiryRow(expiry)}
        ${listTrustIssues}
    `;
}

function renderWeird(data) {

}

/**
 * Render UI cho case WEIRD_WITH_ISSUE
 *
 * Điều kiện:
 * - Hostname sai
 * - Chứng chỉ vẫn được tin cậy
 * - Có trust issue
 *
 * Hiển thị:
 * - Trạng thái trusted
 * - Thông tin ngày hết hạn
 * - Danh sách lỗi trust
 *
 * @param {Object} data - Dữ liệu SSL từ backend
 * @returns {string} HTML
 */
function renderWeirdWithIssue(data) {
    const {
        valid,
        days_left,
        trusted,
        trust_issue,
    } = data;
    const trustedInfo = getTrustedStatus(trusted);
    const expiry = getExpiryInfo(valid, days_left);
    const listTrustIssues = renderTrustIssues(trust_issue);

    return `
        <tr>
            <td class = "result-checker__icon result-checker__icon--trusted-${trustedInfo.iconClass}">&nbsp;</td>
            <td>
                <strong class="result-checker__message result-checker__message-trustedMessage">
                    ${trustedInfo.message}
                </strong>
            </td>
        </tr>
        ${renderExpiryRow(expiry)}
        ${listTrustIssues}
    `;
}

/* ========================================
   HELPER RENDER CERT_CHAIN UI FUNCTIONS
=========================================== */

function renderChainArrow() {
    return `
        <div class="cert-card__arrow-down">
            <img
                src="/client/public/assets/images/tools/ssl/cert_chain/arrow_down.png"
                alt="Chain link"
                loading="lazy"
            >
        </div>
    `;
}

/**
 * Lấy thông tin icon dựa trên level và ngày hết hạn
 *
 * @param {string} level
 * @param {string} notAfterStr
 * @returns {{src: string, alt: string} | null}
 */
function getCertIconData(level, notAfterStr) {

    if (!level || !notAfterStr) return null;

    const levelKey = level.toLowerCase();
    const expireTime = new Date(notAfterStr).getTime();

    // Validate date
    if (Number.isNaN(expireTime)) {
        return null;
    }

    const now = Date.now();
    const statusKey = now < expireTime ? 'VALID' : 'EXPIRED';

    // Map level -> config type
    const configGroup = CERT_CHAIN_CONFIG.LEVEL_MAP[levelKey];

    if (!configGroup) return null;

    const iconData =
        CERT_CHAIN_CONFIG.ICONS[configGroup][statusKey];

    return {
        src: CERT_CHAIN_CONFIG.BASE_PATH + iconData.src,
        alt: iconData.alt
    };
}


/**
 * Render icon cho certificate card
 */
function renderCardIcon(level, not_after) {

    const data = getCertIconData(level, not_after);

    if (!data) return "";

    return `
        <img
            src="${data.src}"
            alt="${data.alt}"
            loading="lazy"
            class="cert-card__img"
        />
    `;
}

/**
 * Format level của certificate để hiển thị trên UI
 * Ví dụ: "domain" → "Domain Certificate"
 *
 * @param {string} level
 * @returns {string}
 */
function renderLevelChain(level) {
    if (!level) return "Unknown";

    return level.charAt(0).toUpperCase()
        + level.slice(1)
        + " Certificate";
}

/**
 * Chuẩn hóa danh sách Subject Alternative Names (SANs)
 * - Đảm bảo luôn trả về mảng
 * - Loại bỏ giá trị rỗng / không hợp lệ
 * - Tránh lỗi khi gọi .join()
 *
 * @param {Array|null|undefined} sans
 * @returns {string[]} Mảng SANs hợp lệ
 */

function getSans(sans) {

    if (!Array.isArray(sans)) return [];
    return sans
        .filter(v => typeof v === "string" && v.trim() !== "")
        .map(v => v.trim());
}

/**
 * Chuẩn hóa danh sách Organization trong chứng chỉ
 * - Đảm bảo luôn trả về mảng
 * - Lọc dữ liệu rác
 * - Dùng an toàn cho render UI
 *
 * @param {Array|null|undefined} organization
 * @returns {string[]} Mảng Organization hợp lệ
 */
function getOrganization(organization) {
    if (!Array.isArray(organization)) return [];

    return organization
        .filter(v => typeof v === "string" && v.trim() !== "")
        .map(v => v.trim());
}

/**
 * Chuẩn hóa và ghép thông tin vị trí của certificate
 * (Locality, Province, Country)
 *
 * Mục đích:
 * - Gom địa điểm phát hành chứng chỉ thành 1 chuỗi hiển thị
 * - Lọc giá trị rỗng / không hợp lệ
 * - Tránh lỗi khi backend trả null
 *
 * Ví dụ output:
 * "Salford, Greater Manchester, GB"
 *
 * @param {Array|null|undefined} locality   Thành phố / Quận
 * @param {Array|null|undefined} province   Tỉnh / Bang / Vùng
 * @param {Array|null|undefined} country    Quốc gia (ISO code)
 *
 * @returns {string} Chuỗi location đã format, hoặc "" nếu không có dữ liệu
 */
function getLocation(locality, province, country) {

    // Gom tất cả field vào 1 mảng
    const parts = [
        ...(Array.isArray(locality) ? locality : []),
        ...(Array.isArray(province) ? province : []),
        ...(Array.isArray(country) ? country : []),
    ];

    // Lọc + trim + join
    return parts
        .filter(v => typeof v === "string" && v.trim() !== "")
        .map(v => v.trim())
        .join(", ");
}

function getNotAfterStatus(notAfter) {

    if (!notAfter) {
        return "expired";
    }

    const expireTime = new Date(notAfter).getTime();

    // Date không hợp lệ
    if (Number.isNaN(expireTime)) {
        return "expired";
    }

    const now = Date.now();

    // Số ngày còn lại
    const daysLeft = Math.floor(
        (expireTime - now) / (1000 * 60 * 60 * 24)
    );

    // Hết hạn
    if (daysLeft < SSL_EXPIRY_THRESHOLDS.EXPIRED) {
        return "expired";
    }

    // Sắp hết hạn
    if (daysLeft < SSL_EXPIRY_THRESHOLDS.WARNING) {
        return "warning";
    }

    // Còn hạn
    return "valid";
}




/* ========================================
   RENDER CERT_CHAIN UI FUNCTIONS
=========================================== */

function renderCertificateChain(cert_chain) {

    const list = cert_chain || [];

    const items = list.map((c, i) => {

        return `
            ${renderCertCard(c)}

            ${i < list.length - 1
                ? renderChainArrow()
                : ""
            }
        `;

    }).join("");

    return `
        <div class="cert-chain d-flex flex-col items-center gap-2">
            ${items}
        </div>
    `;
}


/**
 * Render UI card hiển thị thông tin chi tiết của một certificate trong SSL chain
 *
 * Hiển thị các thông tin chính:
 * - Level (Domain / Intermediate / Root)
 * - Common Name
 * - Issuer
 * - Organization / Country (nếu có)
 * - Subject Alternative Names (SANs) (nếu có)
 * - Thời gian hiệu lực (Valid from → Valid to)
 * - Serial number (hex / dec)
 * - Signature algorithm
 * - Fingerprints (SHA1 / SHA256)
 * - CA flag
 *
 * @param {Object} c - Certificate object từ backend
 *
 * @param {string} c.level - Cấp độ certificate (Domain | Intermediate | Root)
 * @param {string} c.common_name - Common Name của chứng chỉ
 * @param {string} c.issuer - Tên CA phát hành
 *
 * @param {string[]} [c.organization] - Tổ chức phát hành (nếu có)
 * @param {string[]} [c.country] - Quốc gia (nếu có)
 * @param {string[]} [c.locality] - Thành phố (nếu có)
 * @param {string[]} [c.province] - Tỉnh/Bang/Vùng (nếu có)
 *
 * @param {string[]|null} c.sans - Danh sách Subject Alternative Names (SANs)
 *
 * @param {string|Date} c.not_before - Thời điểm bắt đầu hiệu lực
 * @param {string|Date} c.not_after - Thời điểm hết hạn
 *
 * @param {string} c.serial_dec - Serial number dạng decimal
 * @param {string} c.serial_hex - Serial number dạng hex
 *
 * @param {string} c.signature_algo - Thuật toán ký
 *
 * @returns {string} HTML markup của certificate card
 */
function renderCertCard(c) {
    if (!c) return "";

    /* ======
    Get variables
    =========*/
    const {
        level = "",
        common_name: commonName = "",
        issuer = "",
        sans = [],
        organization = [],
        country = [],
        locality = [],
        province = [],
        not_before: notBefore = null,
        not_after: notAfter = null,
        serial_dec: serialDec = "",
        serial_hex: serialHex = "",
        signature_algo: signatureAlgo = "",
    } = c || {};

     const sanList = getSans(sans);
     const orgList = getOrganization(organization);
     const location = getLocation(locality, province, country);
     const notAfterStatus = getNotAfterStatus(notAfter);

    return `
        <div class="cert-card__wrapper d-flex gap-2">
            <div class="cert-card__img-wrapper">
                ${renderCardIcon(level, notAfter)}
            </div>
            <div class="cert-card__content ${level.toLowerCase()} shadow-sm rounded-sm d-flex flex-col gap-1">
                <div class="cert-card__level">
                    <h4 class="cert-card__level-${level.toLowerCase()}">${renderLevelChain(level)}</h4>
                </div>
                <div class="cert-card__info cert-card__common-name">
                    <strong class="cert-card__label">Common Name:&nbsp;</strong>
                    <span class="cert-card__value">${commonName}</span>
                </div>
                ${sanList.length > 0 ? `
                <div class="cert-card__info cert-card__sans">
                    <strong class="cert-card__label">SANs:&nbsp;</strong>
                    <span class="cert-card__value">
                        ${sanList.join(", ")}
                    </span>
                </div>` : ""}
                ${orgList.length > 0 ? `
                <div class="cert-card__info cert-card__org">
                    <strong class="cert-card__label">Organization:&nbsp;</strong>
                    <span class="cert-card__value">
                        ${orgList.join(", ")}
                    </span>
                </div>` : ""}
                ${location.length > 0 ? `
                <div class="cert-card__info cert-card__location">
                    <strong class="cert-card__label">Location:&nbsp;</strong>
                    <span class="cert-card__value">
                        ${location}
                    </span>
                </div>` : ""}
                <div class="cert-card__info cert-card__valid">
                    <strong class="cert-card__label">Valid:&nbsp;</strong>
                    <span class="cert-card__value">
                        From&nbsp;&nbsp; <span class="cert-card__not-before">${formatDate(notBefore)}</span>
                        &nbsp;&nbsp;to&nbsp;&nbsp; <span class="cert-card__not-after ${notAfterStatus}">${formatDate(notAfter)}</span>
                    </span>
                </div>
                <div class="cert-card__info cert-card__serial-number">
                    <strong class="cert-card__label">Serial Number:&nbsp;</strong>
                    <span class="cert-card__value" title="Decimal Format: ${serialDec}">${serialHex}</span>
                </div>
                <div class="cert-card__info cert-card__signature-algo">
                    <strong class="cert-card__label">Signature Algorithm:&nbsp;</strong>
                    <span class="cert-card__value">${signatureAlgo}</span>
                </div>
                <div class="cert-card__info cert-card__issuer">
                    <strong class="cert-card__label">Issuer:&nbsp;</strong>
                    <span class="cert-card__value">${issuer}</span>
                </div>
            </div>
        </div>
    `;
}

/* =================================
    HELPER SHARE LINK FUNCTION
================================== */

function buildURLWithHostname(hostname) {
    if (!hostname) return "";

    const url = new URL(window.location.href);

    url.searchParams.set("hostname", hostname);

    return url.toString();
}


/* =================================
    PERFORM SSL CHECKER FUNCTIONS
================================== */
async function performSSLChecker(domain) {

    const url = `${API_BASE_URL}/ssl/check?domain=${encodeURIComponent(domain)}`;

    try {
        const response = await fetch(url, {
            method: "GET",
            headers: {
                Accept: "application/json",
            },
        });

        let data = {};

        try {
            data = await response.json();
        } catch {
            data = {};
        }
        if (!response.ok) {
            return {
                success: false,
                code: response.status,
                error: data?.error || "Server error",
            };
        }

        return data;

    } catch (err) {

        console.error("Network error:", err);

        return {
            success: false,
            error: "Không thể kết nối server",
            code: 0,
        };
    }
}

/* =================================
    UI RENDER SUMARY FUNCTIONS
================================== */
/**
 * Hiển thị kết quả tra cứu SSL
 *
 * @param {object} data - Dữ liệu kết quả từ API
 */
function displayResults(data) {

    setDisplay(toolResultChecker, "block");

    // Nếu không có data
    if (!data) {
        renderFatalError(data.error || "Không nhận được dữ liệu từ server");
        return;
    }

    // Nếu backend báo lỗi
    if (data.success === false) {

        resultDomainName.textContent = data.hostname || "N/A";
        btnWhoisChecker.onclick = null;

        // Lỗi do user / giới hạn
        if (data.code === 422 || data.code === 429) {

            setDisplay(resultCheckerHeader, "flex");
            getWhoisDomain(btnWhoisChecker, data.hostname);


            showError(
                toolError,
                toolErrorMessage,
                data.error || "Không thể tra cứu",
                [resultCheckerContent, toolShareLink]
            );

            return;
        }

        // Lỗi hệ thống
        renderFatalError(data.error || "Hệ thống đang bận, vui lòng thử lại sau.");

        return;
    }

    // ===== SUCCESS =====

    resultDomainName.textContent = data.hostname;
    setDisplay(resultCheckerHeader, "flex");
    getWhoisDomain(btnWhoisChecker, data.hostname);
    showElements("block", resultCheckerContent, toolShareLink);
    const shareLink = buildURLWithHostname(data.hostname);
    shareLinkChecker.value = shareLink;

    // showElements("block", resultCheckerContent);
    setDisplay(toolError, "none");

    renderSSLResult(data);
}

/**
 * Render kết quả kiểm tra SSL cho một hostname
 *
 * Luồng xử lý:
 * 1. Chuẩn hóa trạng thái trust (getTrustState)
 * 2. Phát hiện case logic (detectCase)
 * 3. Render UI theo case (renderByCase)
 *
 * @param {Object} data - Dữ liệu SSL trả về từ backend
 * @returns {string} HTML hoàn chỉnh
 */
function renderSSLResult(data) {
    const {
        hostname,
        ip,
        days_left,
        server_type,
        trusted,
        tls_version,
        hostname_ok,
        cert_chain,
    } = data;

    /* =========================
        1. TRUST STATE
    ========================== */

    const trustState = getTrustState({
        hostname_ok,
        trusted,
        trust_issue: data.trust_issue
    });

    /* =========================
        2. DETECT CASE
    ========================== */

    const caseType = detectCase(trustState);

    /* =========================
        3. RENDER CORE CONTENT
    ========================== */

    const badge = getBadgeStatus(trusted, days_left);
    const tlsversion = getTSLInfo(tls_version);
    const summaryContentHTML = renderByCase(caseType, data);
    const certificateChain = renderCertificateChain(cert_chain);
    const issuerBrand = getIssuerBrand(cert_chain);
    const issuerText = getIssuerStatus(issuerBrand);
    const issuerLogoPath = getIssuerLogoPath(issuerBrand, issuerLogoMap);

    resultCheckerContent.innerHTML = `
        <div class="result-checker__overview d-flex flex-row gap-2 items-center">
            <span class="result-checker__icon result-checker__icon--result"></span>
            <h3 class="result-checker__overview-title">
                Kết quả tổng quan:
            </h3>
            <span class="result-checker__badge result-checker__badge--${badge.toLowerCase()} rounded-sm">
                <span class="result-checker__badge-icon result-checker__badge-icon--${badge.toLowerCase()}">
                    &nbsp;
                </span>
                ${badge.toUpperCase()}
            </span>
        </div>
        <table class="result-checker__table">
            <tbody>
                <tr>
                    <td class="result-checker__icon result-checker__icon--resolve">&nbsp;</td>
                    <td>
                        <span class="result-checker__message">
                            Tên miền <strong class="result-checker__message--value result-checker__message--hostname">${escapeHTML(safe(hostname))}</strong> được phân giải thành địa chỉ IP <strong class="result-checker__message--value result-checker__message--ip">${escapeHTML(safe(ip))}</strong>.
                        </span>
                    </td>
                </tr>
                <tr>
                    <td class="result-checker__icon result-checker__icon--server">&nbsp;</td>
                    <td>
                        <span class="result-checker__message">
                            Server Type: <strong class="result-checker__message--value result-checker__message--serverType">${escapeHTML(server_type)}</strong>.
                        </span>
                    </td>
                </tr>
                ${issuerText ? `
                <tr>
                    <td class="result-checker__icon result-checker__icon--issuer">&nbsp;</td>
                    <td >
                        <span class="result-checker__message d-flex items-center">${issuerText} ${renderIssuerLogoHTML(issuerBrand, issuerLogoPath)}</span>
                    </td>
                </tr>` : ""}
                ${tlsversion.message ? `
                <tr>
                    <td class = "result-checker__icon result-checker__icon--tls ${tlsversion.iconClass}">&nbsp;</td>
                    <td >
                        <span class="result-checker__message">
                            Giao thức kết nối:
                            <strong class="result-checker__message--value result-checker__message--tls">
                                ${tlsversion.message}.&nbsp;
                            </strong>
                            <strong class="result-checker__message--value result-checker__message--tlsStatus ${tlsversion.iconClass}">
                            (${(tlsversion.iconClass).toUpperCase()})
                            </strong>
                        </span>
                    </td>
                </tr>` : ""}
                ${summaryContentHTML}
            </tbody>
        </table>
            ${certificateChain}

    `;

}
/* =================================
    URL FUNCTIONS
================================== */
/**
 * Đổi link URL
 *
 * @param {string} domain - Tên miền để thêm vào URL
 */
function updateURL(hostname) {
    if (!hostname) return;

    const url = new URL(window.location.href);

    url.searchParams.set("hostname", hostname);

    window.history.pushState({}, "", url.toString());
}


function handleURLParams() {
    const urlParams = new URLSearchParams(window.location.search);
    const hostname = urlParams.get("hostname");

    if (hostname) {
        inputChecker.value = hostname;
    }

    // Auto submit if all params present
    if (hostname) {
        setTimeout(() => {
            formChecker.dispatchEvent(new Event("submit"));
        }, 500);
    }
}



/* =================================
    EVENT BINDINGS
================================== */
if (formChecker) {
    formChecker.addEventListener("submit", async (e) => {
        e.preventDefault();
        resetUI([toolResultChecker, toolShareLink, toolError]);
        toggleLoading(btnSubmitChecker, iconCheckerArrow, iconCheckerLoading, true);
        const hostname = normalizeHostnameInput(inputChecker.value.trim());
        if (!hostname) return;
        inputChecker.value = hostname;
        updateURL(hostname);

        try {
            const result = await performSSLChecker(hostname);
            displayResults(result);
        } catch (error) {
            const msg = error?.message || "Không thể tra cứu SSL. Vui lòng thử lại.";
            showError(toolError, toolErrorMessage, msg, [toolShareLink, toolResultChecker]);
        } finally {
            toggleLoading(btnSubmitChecker, iconCheckerArrow, iconCheckerLoading, false);
        }
    });
}

// =================================//
//  APP LIFECYCLE
//==================================//
function initApp() {
    handleURLParams();
    inputChecker.focus();

    // Init copy button
    setupCopyButton(shareLinkChecker, btnCopyLinkChecker);

    console.log("🚀 SSL Checker Tool Initialized");
}


document.addEventListener("DOMContentLoaded", initApp);
