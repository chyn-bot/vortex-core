/**
 * Vortex Application JavaScript
 * HTMX extensions and utilities
 */

// Configure HTMX
document.addEventListener('DOMContentLoaded', function() {
    // Add CSRF token to all HTMX requests
    document.body.addEventListener('htmx:configRequest', function(event) {
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
        if (csrfToken) {
            event.detail.headers['X-CSRF-Token'] = csrfToken;
        }
    });

    // Handle HTMX errors
    document.body.addEventListener('htmx:responseError', function(event) {
        const status = event.detail.xhr.status;

        if (status === 401) {
            // Unauthorized - redirect to login
            window.location.href = '/login';
        } else if (status === 403) {
            showToast('Access denied', 'error');
        } else if (status === 422) {
            // Validation error - handled by the response
        } else if (status >= 500) {
            showToast('Server error. Please try again.', 'error');
        }
    });

    // Handle successful form submissions
    document.body.addEventListener('htmx:afterRequest', function(event) {
        const xhr = event.detail.xhr;

        // Check for success messages in response headers
        const successMessage = xhr.getResponseHeader('X-Success-Message');
        if (successMessage) {
            showToast(successMessage, 'success');
        }

        // Check for redirect
        const redirectUrl = xhr.getResponseHeader('X-Redirect');
        if (redirectUrl) {
            window.location.href = redirectUrl;
        }
    });

    // Close dropdowns when clicking outside
    document.addEventListener('click', function(event) {
        if (!event.target.closest('.dropdown')) {
            document.querySelectorAll('.dropdown-content').forEach(function(dropdown) {
                dropdown.classList.remove('dropdown-open');
            });
        }
    });
});

/**
 * Show a toast notification
 * @param {string} message - The message to display
 * @param {string} type - The type: 'success', 'error', 'warning', 'info'
 * @param {number} duration - Duration in ms (default 5000)
 */
function showToast(message, type = 'info', duration = 5000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const alertClass = {
        'success': 'alert-success',
        'error': 'alert-error',
        'warning': 'alert-warning',
        'info': 'alert-info'
    }[type] || 'alert-info';

    const icon = {
        'success': '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>',
        'error': '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/>',
        'warning': '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>',
        'info': '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>'
    }[type] || '';

    const toast = document.createElement('div');
    toast.className = `alert ${alertClass} shadow-lg`;
    toast.innerHTML = `
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">${icon}</svg>
        <span>${escapeHtml(message)}</span>
        <button class="btn btn-ghost btn-sm" onclick="this.parentElement.remove()">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
        </button>
    `;

    container.appendChild(toast);

    // Auto-remove after duration
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

/**
 * Open a modal dialog
 * @param {string} url - URL to fetch modal content from
 */
function openModal(url) {
    const container = document.getElementById('modal-container');
    if (!container) return;

    fetch(url, {
        headers: {
            'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || ''
        }
    })
    .then(response => response.text())
    .then(html => {
        container.innerHTML = html;
        const modal = container.querySelector('.modal');
        if (modal) {
            modal.classList.add('modal-open');
        }
    })
    .catch(error => {
        showToast('Failed to load modal', 'error');
    });
}

/**
 * Close the current modal
 */
function closeModal() {
    const container = document.getElementById('modal-container');
    if (!container) return;

    const modal = container.querySelector('.modal');
    if (modal) {
        modal.classList.remove('modal-open');
        setTimeout(() => container.innerHTML = '', 200);
    }
}

/**
 * Confirm a destructive action
 * @param {string} message - Confirmation message
 * @param {function} onConfirm - Callback if confirmed
 */
function confirmAction(message, onConfirm) {
    const container = document.getElementById('modal-container');
    if (!container) return;

    container.innerHTML = `
        <div class="modal modal-open">
            <div class="modal-box">
                <h3 class="font-bold text-lg">Confirm Action</h3>
                <p class="py-4">${escapeHtml(message)}</p>
                <div class="modal-action">
                    <button class="btn" onclick="closeModal()">Cancel</button>
                    <button class="btn btn-error" id="confirm-btn">Confirm</button>
                </div>
            </div>
            <div class="modal-backdrop" onclick="closeModal()"></div>
        </div>
    `;

    document.getElementById('confirm-btn').addEventListener('click', function() {
        closeModal();
        onConfirm();
    });
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Format a date for display
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }).format(date);
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard', 'success', 2000);
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

/**
 * Debounce function calls
 * @param {function} func - Function to debounce
 * @param {number} wait - Wait time in ms
 * @returns {function} Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Export for use in other scripts
window.Vortex = {
    showToast,
    openModal,
    closeModal,
    confirmAction,
    formatDate,
    copyToClipboard,
    debounce
};
