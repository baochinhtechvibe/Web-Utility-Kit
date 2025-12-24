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
    }

    /**
     * Initialize theme toggle
     * Call this after DOM elements are loaded
     */
    init() {
        // Get DOM elements
        this.btnThemeToggle = document.getElementById('btn-theme-toggle');
        this.themeLabel = document.getElementById('theme-label');

        // Check if elements exist
        if (!this.btnThemeToggle) {
            console.error('[ThemeToggle] Button #btn-theme-toggle not found');
            return false;
        }

        // Prevent double initialization
        if (this.isInitialized) {
            console.warn('[ThemeToggle] Already initialized');
            return false;
        }

        // Load saved theme or default to light
        this.loadSavedTheme();

        // Add event listener
        this.btnThemeToggle.addEventListener('click', () => this.toggle());

        this.isInitialized = true;
        console.log('[ThemeToggle] Initialized successfully');
        return true;
    }

    /**
     * Load theme from localStorage
     */
    loadSavedTheme() {
        const savedTheme = localStorage.getItem(this.storageKey);

        if (savedTheme && (savedTheme === 'light' || savedTheme === 'dark')) {
            this.setTheme(savedTheme);
        } else {
            // Default theme
            this.setTheme('light');
        }
    }

    /**
     * Toggle between light and dark theme
     */
    toggle() {
        const currentTheme = this.html.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
    }

    /**
     * Set theme and update UI
     * @param {string} theme - 'light' or 'dark'
     */
    setTheme(theme) {
        // Validate theme value
        if (theme !== 'light' && theme !== 'dark') {
            console.error(`[ThemeToggle] Invalid theme: ${theme}`);
            return;
        }

        // Update HTML attribute
        this.html.setAttribute('data-theme', theme);

        // Save to localStorage
        localStorage.setItem(this.storageKey, theme);

        // Update UI
        this.updateUI(theme);
    }

    /**
     * Update button icon and label
     * @param {string} theme - Current theme
     */
    updateUI(theme) {
        if (!this.btnThemeToggle) return;

        const icon = this.btnThemeToggle.querySelector('i');
        if (!icon) return;

        if (theme === 'dark') {
            // Dark mode active → Show sun icon (to switch to light)
            icon.classList.remove('fa-moon');
            icon.classList.add('fa-sun', 'icon--yellow');

            // Update button aria-label
            this.btnThemeToggle.setAttribute('aria-label', 'Switch to light mode');

            // Update tooltip text
            if (this.themeLabel) {
                this.themeLabel.textContent = 'Light Mode';
            }
        } else {
            // Light mode active → Show moon icon (to switch to dark)
            icon.classList.remove('fa-sun', 'icon--yellow');
            icon.classList.add('fa-moon');

            // Update button aria-label
            this.btnThemeToggle.setAttribute('aria-label', 'Switch to dark mode');

            // Update tooltip text
            if (this.themeLabel) {
                this.themeLabel.textContent = 'Dark Mode';
            }
        }
    }

    /**
     * Get current theme
     * @returns {string} Current theme ('light' or 'dark')
     */
    getCurrentTheme() {
        return this.html.getAttribute('data-theme') || 'light';
    }

    /**
     * Destroy theme toggle (cleanup)
     */
    destroy() {
        if (this.btnThemeToggle) {
            this.btnThemeToggle.removeEventListener('click', this.toggle);
        }
        this.isInitialized = false;
    }
}

// Create singleton instance
const themeToggle = new ThemeToggle();

// Expose globally for manual initialization (when loading partials)
window.themeToggle = themeToggle;

// Note: init() will be called by load-partials.js after header/footer are loaded

// Export for module usage (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThemeToggle;
}