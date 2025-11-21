document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form[action="/upload_scan"]');
    if (form) {
        form.addEventListener('submit', function(event) {
            const spinner = document.getElementById('loadingSpinner');
            const button = form.querySelector('button[type="submit"]');

            if (spinner) {
                spinner.classList.remove('d-none');
            }
            if (button) {
                button.setAttribute('disabled', 'disabled');
                button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Scanning...';
            }
        });
    }
});