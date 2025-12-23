const btnThemeToggle = document.getElementById("btn-theme-toggle"); // Lấy nút toggle
const html = document.documentElement; //Lấy thẻ html
const valueTheme = localStorage.getItem("theme"); //
const themeLabel = document.getElementById("theme-label");

/* Kiểm tra xem savedTheme có tồn tại và có giá trị truthy không, nếu có, thêm thuộc tính data-theme trên thẻ <html> */
if (valueTheme) {
    html.setAttribute("data-theme", valueTheme);
    updateIcon(valueTheme);
}

/* Bắt sự kiện click vào nút toggle*/
btnThemeToggle.addEventListener('click', () => {
    const currentTheme = html.getAttribute("data-theme");

    if (currentTheme === "dark") {
        setTheme("light");
    } else {
        setTheme("dark");
    }
});

function setTheme(theme) {
    html.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
    updateIcon(theme);
}

function updateIcon(theme) {
    const icon = btnThemeToggle.querySelector("i");
    if (theme === "dark") {
        // Cập nhật icon
        icon.classList.remove("fa-moon");
        icon.classList.add("fa-sun");
        icon.classList.add("icon--yellow");

        // Cập nhật aria-label cho button
        btnThemeToggle.setAttribute("aria-label", "Switch to light mode");

        // Cập nhật text trong tooltip
        themeLabel.textContent = "Light Mode";

    } else {
        icon.classList.remove("fa-sun");
        icon.classList.remove("icon--yellow");
        icon.classList.add("fa-moon");
        btnThemeToggle.setAttribute("aria-label", "Switch to dark mode");
        themeLabel.textContent = "Dark Mode"
    }
}