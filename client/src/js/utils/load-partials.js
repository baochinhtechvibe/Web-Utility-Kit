/**
 * Partial Loader
 * Loads HTML partials (header, footer) into placeholders
 */

class PartialLoader {
    constructor() {
        this.loadedPartials = new Set();
        this.loadingPromises = new Map();
    }

    /**
     * Load a single partial HTML file
     * @param {string} elementId - ID of placeholder element
     * @param {string} filePath - Path to HTML file
     * @returns {Promise<void>}
     */
    async loadPartial(elementId, filePath) {
        // Prevent duplicate loading
        if (this.loadedPartials.has(elementId)) {
            console.log(`[PartialLoader] ${elementId} already loaded`);
            return;
        }

        // Return existing promise if already loading
        if (this.loadingPromises.has(elementId)) {
            return this.loadingPromises.get(elementId);
        }

        const loadPromise = this._fetchAndInject(elementId, filePath);
        this.loadingPromises.set(elementId, loadPromise);

        try {
            await loadPromise;
            this.loadedPartials.add(elementId);
            this.loadingPromises.delete(elementId);
        } catch (error) {
            this.loadingPromises.delete(elementId);
            throw error;
        }
    }

    /**
     * Internal method to fetch and inject HTML
     * @private
     */
    async _fetchAndInject(elementId, filePath) {
        const element = document.getElementById(elementId);

        if (!element) {
            throw new Error(`[PartialLoader] Element #${elementId} not found`);
        }

        try {
            console.log(`[PartialLoader] Loading ${filePath}...`);

            const response = await fetch(filePath);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const html = await response.text();
            element.innerHTML = html;

            console.log(`[PartialLoader] ✓ Loaded ${filePath} into #${elementId}`);
        } catch (error) {
            console.error(`[PartialLoader] Failed to load ${filePath}:`, error);

            // Show error message in placeholder
            element.innerHTML = `
                <div style="padding: 1rem; background: #fee; color: #c00; border: 1px solid #fcc; border-radius: 4px;">
                    <strong>Error loading ${filePath}</strong><br>
                    ${error.message}
                </div>
            `;

            throw error;
        }
    }

    /**
     * Load multiple partials in parallel
     * @param {Array<{id: string, path: string}>} partials
     * @returns {Promise<void>}
     */
    async loadAll(partials) {
        const promises = partials.map(partial =>
            this.loadPartial(partial.id, partial.path)
        );

        await Promise.all(promises);
    }

    /**
     * Reload a specific partial
     * @param {string} elementId
     * @param {string} filePath
     */
    async reload(elementId, filePath) {
        this.loadedPartials.delete(elementId);
        await this.loadPartial(elementId, filePath);
    }

    /**
     * Check if a partial is loaded
     * @param {string} elementId
     * @returns {boolean}
     */
    isLoaded(elementId) {
        return this.loadedPartials.has(elementId);
    }
}

// Create singleton instance
const partialLoader = new PartialLoader();

/**
 * Initialize app after partials are loaded
 */
async function initApp() {
    try {
        console.log('[App] Loading partials...');

        // Load header and footer
        await partialLoader.loadAll([
            { id: 'header-placeholder', path: './partials/header.html' },
            { id: 'footer-placeholder', path: './partials/footer.html' }
        ]);

        console.log('[App] ✓ All partials loaded');

        // Initialize theme toggle after header is loaded
        if (window.themeToggle) {
            console.log('[App] Initializing theme toggle...');
            window.themeToggle.init();
        } else {
            console.warn('[App] ThemeToggle not found on window object');
        }

        // Dispatch custom event for other scripts
        window.dispatchEvent(new CustomEvent('partials-loaded'));
        console.log('[App] ✓ App initialized');

    } catch (error) {
        console.error('[App] Initialization failed:', error);
    }
}

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

// Expose globally
window.partialLoader = partialLoader;

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PartialLoader;
}