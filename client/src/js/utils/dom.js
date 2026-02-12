// js/utils/dom.js

/*
===============================================
    DOM / UI HELPER FUNCTIONS
    Các hàm hỗ trợ thao tác giao diện (display,
    loading, error, query selector...)
=================================================
*/


// ================================
// DISPLAY CONTROL
// Quản lý hiển thị element bằng utility class
// ================================

/**
 * Thay đổi trạng thái hiển thị của element
 * bằng các class d-* (Bootstrap / custom)
 *
 * @param {HTMLElement} el
 * @param {string} mode - none | block | flex | inline | inline-block
 */
export function setDisplay(el, mode = "none") {

    if (!el) return;

    const classes = [
        "d-none",
        "d-block",
        "d-flex",
        "d-inline",
        "d-inline-block"
    ];

    // Xóa toàn bộ class display cũ
    el.classList.remove(...classes);

    // Gắn class mới
    if (mode) {
        el.classList.add(`d-${mode}`);
    }
}


/**
 * Hiển thị element (display: block)
 *
 * @param {HTMLElement} el
 */
export function show(el) {
    setDisplay(el, "block");
}


/**
 * Ẩn element (display: none)
 *
 * @param {HTMLElement} el
 */
export function hide(el) {
    setDisplay(el, "none");
}

/**
 * Reset UI bằng cách ẩn danh sách element truyền vào
 *
 * @param {HTMLElement[]} elements
 */
export function resetUI(elements = []) {
    showElements("none", ...elements);
}




// ================================
// MULTI DISPLAY
// Hiển thị / ẩn nhiều element cùng lúc
// ================================

/**
 * Hiển thị nhiều element theo mode
 *
 * @param {string} mode
 * @param {...HTMLElement} elements
 */
export function showElements(mode, ...elements) {

    elements.forEach(el => {

        if (el) {
            setDisplay(el, mode);
        }

    });
}



// ================================
// LOADING STATE
// Quản lý trạng thái loading cho button
// ================================

/**
 * Bật / tắt trạng thái loading cho button
 *
 * - Disable button khi loading
 * - Ẩn icon thường
 * - Hiện icon loading
 *
 * @param {HTMLButtonElement} button
 * @param {HTMLElement} normalIcon
 * @param {HTMLElement} loadingIcon
 * @param {boolean} isLoading
 */
export function toggleLoading(
    button,
    normalIcon,
    loadingIcon,
    isLoading = true
) {

    if (!button) return;

    // Disable / enable button
    button.disabled = isLoading;

    // Toggle icon hiển thị
    normalIcon?.classList.toggle("d-none", isLoading);

    loadingIcon?.classList.toggle("d-none", !isLoading);
}



// ================================
// ERROR DISPLAY
// Hiển thị lỗi và ẩn các section khác
// ================================

/**
 * Hiển thị section lỗi kèm message
 * và ẩn các section không liên quan
 *
 * @param {HTMLElement} section - Section hiển thị lỗi
 * @param {HTMLElement} messageEl - Element chứa nội dung lỗi
 * @param {string} message - Nội dung lỗi
 * @param {HTMLElement[]} hideSections - Các section cần ẩn
 */
export function showError(
    section,
    messageEl,
    message,
    hideSections = []
) {

    if (!section || !messageEl) return;

    // Set nội dung lỗi
    messageEl.textContent = message;

    // Hiện section lỗi
    setDisplay(section, "block");

    // Ẩn các section khác
    hideSections.forEach(el => {
        setDisplay(el, "none");
    });

    // Scroll tới vị trí lỗi
    section.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}



// ================================
// SHORT QUERY SELECTORS
// Rút gọn querySelector
// ================================

/**
 * querySelector rút gọn
 *
 * @param {string} s
 * @param {HTMLElement|Document} scope
 * @returns {HTMLElement|null}
 */
export const $ = (s, scope = document) =>
    scope.querySelector(s);


/**
 * querySelectorAll rút gọn
 *
 * @param {string} s
 * @param {HTMLElement|Document} scope
 * @returns {NodeListOf<Element>}
 */
export const $$ = (s, scope = document) =>
    scope.querySelectorAll(s);
