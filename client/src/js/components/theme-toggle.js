/**
 * Theme Toggle Manager
 * Handles light/dark mode switching with localStorage persistence
 */

class ThemeToggle {
    constructor() {
        this.html = document.documentElement;
        this.storageKey = 'theme';
        this.btnThemeToggle = null;
        this.themeLabel = null;
        this.isInitialized = false;

        // Auto init when DOM is ready
        document.addEventListener('DOMContentLoaded', () => {
            this.init();
        });
    }

    /**
     * Initialize theme toggle
     */
    init() {
        if (this.isInitialized) return;

        // Get DOM elements
        this.btnThemeToggle = document.getElementById('btn-theme-toggle');
        this.themeLabel = document.getElementById('theme-label');

        if (!this.btnThemeToggle) {
            console.warn('[ThemeToggle] #btn-theme-toggle not found');
            return;
        }

        // Load saved theme
        this.loadSavedTheme();

        // Bind event
        this.handleToggle = () => this.toggle();
        this.btnThemeToggle.addEventListener('click', this.handleToggle);

        this.isInitialized = true;
        console.log('[ThemeToggle] Initialized');
    }

    /**
     * Load theme from localStorage
     */
    loadSavedTheme() {
        const savedTheme = localStorage.getItem(this.storageKey);
        this.setTheme(savedTheme === 'dark' ? 'dark' : 'light');
    }

    /**
     * Toggle theme
     */
    toggle() {
        const currentTheme = this.getCurrentTheme();
        this.setTheme(currentTheme === 'dark' ? 'light' : 'dark');
    }

    /**
     * Apply theme
     * @param {string} theme
     */
    setTheme(theme) {
        if (!['light', 'dark'].includes(theme)) return;

        this.html.setAttribute('data-theme', theme);
        localStorage.setItem(this.storageKey, theme);
        this.updateUI(theme);
    }

    /**
     * Update icon + label
     * @param {string} theme
     */
    updateUI(theme) {
        if (!this.btnThemeToggle) return;

        const icon = this.btnThemeToggle.querySelector('i');
        if (!icon) return;

        if (theme === 'dark') {
            icon.classList.remove('fa-moon');
            icon.classList.add('fa-sun', 'icon--yellow');
            this.btnThemeToggle.setAttribute('aria-label', 'Switch to light mode');
            if (this.themeLabel) this.themeLabel.textContent = 'Light Mode';
        } else {
            icon.classList.remove('fa-sun', 'icon--yellow');
            icon.classList.add('fa-moon');
            this.btnThemeToggle.setAttribute('aria-label', 'Switch to dark mode');
            if (this.themeLabel) this.themeLabel.textContent = 'Dark Mode';
        }
    }

    /**
     * Get current theme
     */
    getCurrentTheme() {
        return this.html.getAttribute('data-theme') || 'light';
    }

    /**
     * Cleanup
     */
    destroy() {
        if (this.btnThemeToggle && this.handleToggle) {
            this.btnThemeToggle.removeEventListener('click', this.handleToggle);
        }
        this.isInitialized = false;
    }
}

// Create instance (auto-init)
new ThemeToggle();
