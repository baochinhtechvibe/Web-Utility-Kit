// ===================================================
//  SSL TOOLS - CSR DECODER PAGE
// ===================================================
import {
    /* dom.js */
    toggleLoading,
    setDisplay,
    renderSuccessHeader,
    showElements,
    resetUI,
    setElementsEnabled,
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
 * CSR Decoder Elements
 */
const formCsr = document.getElementById("formCsrDecoder");
const inputCsr = document.getElementById("inputCsr");
const btnCsrDecoder = document.getElementById("btnCsrDecoder");
const iconCsrDecoder = document.getElementById("iconCsrDecoder");
const iconCsrLoading = document.getElementById("iconCsrLoading");
const toolResult = document.getElementById("toolResult");
const sslResultTitle = document.getElementById("sslResultTitle");
const resultsContent = document.getElementById("resultsContent");
const toolError = document.getElementById("toolError");
const toolErrorTitle = document.getElementById("toolErrorTitle");
const toolErrorMessage = document.getElementById("toolErrorMessage");

const CSR_STORAGE_KEY = "web_utility_kit_csr_decoder_input";

/* ================================
    HELPER FUNCTIONS
=================================== */
/**
 * Chuẩn hóa dữ liệu CSR người dùng nhập
 *
 * Mục đích:
 * - Đảm bảo CSR ở dạng PEM hợp lệ
 * - Chỉ cho phép 1 block BEGIN/END
 * - Chuẩn hóa xuống dòng và khoảng trắng
 *
 * Xử lý:
 * - Trim khoảng trắng
 * - Chuẩn hóa newline về \n
 * - Extract đúng 1 PEM block
 * - Remove khoảng trắng thừa giữa base64
 *
 * @param {string} input - CSR người dùng nhập
 * @returns {string} CSR đã chuẩn hóa (PEM)
 * @throws {Error} nếu CSR không hợp lệ
 */
function normalizeCSRInput(input) {

    if (input == null || typeof input !== "string") return "";
    if (input.trim() === "") return "";

    const MAX_CSR_SIZE = 100 * 1024;
    if (input.length > MAX_CSR_SIZE) {
        throw new Error("CSR vượt quá kích thước cho phép (100KB).");
    }

    input = input.trim()
        .replace(/\r\n/g, "\n")
        .replace(/\r/g, "\n");

    const STRICT_PEM_REGEX =
        /^\s*-----BEGIN ((?:NEW )?CERTIFICATE REQUEST)-----([\s\S]*?)-----END \1-----\s*$/;

    const match = input.match(STRICT_PEM_REGEX);

    if (!match) {
        throw new Error("CSR không hợp lệ: Không tìm thấy PEM hợp lệ.");
    }

    const [, type, rawBase64] = match;

    const base64Content = rawBase64.replace(/\s+/g, "");

    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64Content)) {
        throw new Error("CSR không hợp lệ: Base64 chứa ký tự không hợp lệ.");
    }

    if (base64Content.length % 4 !== 0) {
        throw new Error("CSR không hợp lệ: Base64 bị truncated hoặc thiếu padding.");
    }

    const lines = [];
    for (let i = 0; i < base64Content.length; i += 64) {
        lines.push(base64Content.slice(i, i + 64));
    }

    return `-----BEGIN ${type}-----\n${lines.join("\n")}\n-----END ${type}-----`;
}

/* =================================
    PERFORM CSR DECODER FUNCTIONS
================================== */
/**
 * Gửi CSR lên server để decode
 *
 * @param {string} csr - CSR đã được normalize
 * @returns {Promise<{success: boolean, data?: any, error?: string, code?: number}>}
 */
async function performCSRDecoder(csr) {

    if (typeof csr !== "string" || csr.trim() === "") {
        return {
            success: false,
            error: "CSR không hợp lệ",
            code: 400,
        };
    }

    const url = `${API_BASE_URL}/ssl/csr/decode`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    try {
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body: JSON.stringify({ csr }),
            signal: controller.signal,
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

        // ✅ Thành công → trả nguyên data server
        return data;

    } catch (err) {

        if (err.name === "AbortError") {
            return {
                success: false,
                error: "Request timeout",
                code: 408,
            };
        }

        console.error("CSR decode network error:", err);

        return {
            success: false,
            error: "Không thể kết nối server",
            code: 0,
        };

    } finally {
        clearTimeout(timeoutId);
    }
}

/* =================================
    UI RENDER FUNCTIONS
================================== */
/**
 * Hiển thị kết quả giải mã CSR
 *
 * @param {object} data - Dữ liệu kết quả từ API
 */
function displayResults(data) {
    // Fail fast: không có data hoặc backend báo lỗi
    if (!data || data.success === false) {
        showError(
            toolError,
            toolErrorMessage,
            data?.error || "Giải mã CSR thất bại, vui lòng thử lại sau",
            [toolResult]
        );
        return;
    }

    setDisplay(toolResult, "flex");
    setDisplay(toolError, "none");
    renderSuccessHeader(sslResultTitle, "Kết quả giải mã CSR:");
    renderCSRResult(data);
}

function renderCSRResult(data) {
    if (!data) return;
    const {
        common_name,
        organization,
        organizational_unit,
        country,
        state,
        locality,
        sans,
        key_size,
        algorithm,
    } = data;

    resultsContent.innerHTML = `
        <div class="resultDecode__wrapper">
            <div class="resultDecode__row">
                <div class="resultDecode__label">
                    <i class="fa-solid fa-circle-check" style="color: #198754;"></i>
                    Common Name
                </div>
                <div class="resultDecode__value">${common_name || "N/A"}</div>
            </div>
            <div class="resultDecode__row">
                <div class="resultDecode__label">
                    <i class="fa-solid fa-circle-check" style="color: #198754;"></i>
                    Sans
                </div>
                <div class="resultDecode__value">${sans.join(", ") || "N/A"}</div>
            </div>
        </div>
    `;


}

/* =================================
    EVENT BINDINGS
================================== */
if (formCsr) {
    formCsr.addEventListener("submit", async (e) => {
        e.preventDefault();
        setElementsEnabled([inputCsr, btnCsrDecoder], false);
        resetUI([toolResult, toolError]);
        toggleLoading(btnCsrDecoder, iconCsrDecoder, iconCsrLoading, true);

        const csr = normalizeCSRInput(inputCsr.value);

        try {
            const result = await performCSRDecoder(csr);
            displayResults(result);
        } catch (error) {
            const msg = error?.message || "Không thể giải mã CSR. Vui lòng thử lại.";
            showError(toolError, toolErrorMessage, msg, [toolResult]);
        } finally {
            toggleLoading(btnCsrDecoder, iconCsrDecoder, iconCsrLoading, false);
            setElementsEnabled([inputCsr, btnCsrDecoder], true);
        }


    });
}

// =================================//
//  APP LIFECYCLE
//==================================//
function initApp() {
    const savedCSR = localStorage.getItem(CSR_STORAGE_KEY);
    if (savedCSR) {
        inputCsr.value = savedCSR;
    }

    // Auto save khi user nhập
    inputCsr.addEventListener("input", () => {
        localStorage.setItem(CSR_STORAGE_KEY, inputCsr.value);
    });

    inputCsr.focus();
    console.log("🚀 CSR Decoder Tool Initialized");
}


document.addEventListener("DOMContentLoaded", initApp);