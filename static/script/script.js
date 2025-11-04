// Fungsi untuk menangani drag and drop file
function initializeFileUpload() {
    const fileUploadAreas = document.querySelectorAll('.file-upload-area');

    fileUploadAreas.forEach(area => {
        const fileInput = area.querySelector('.file-input');
        const fileLabel = area.querySelector('.file-label');
        const fileSubtext = area.querySelector('.file-subtext');

        // Click event
        area.addEventListener('click', (e) => {
            if (!e.target.classList.contains('file-input')) {
                fileInput.click();
            }
        });

        // Drag and drop events
        area.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
            area.classList.add('dragover');
        });

        area.addEventListener('dragenter', (e) => {
            e.preventDefault();
            e.stopPropagation();
            area.classList.add('dragover');
        });

        area.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (!area.contains(e.relatedTarget)) {
                area.classList.remove('dragover');
            }
        });

        area.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            area.classList.remove('dragover');

            const files = e.dataTransfer.files;
            if (files.length) {
                handleFileSelection(files[0], fileInput, fileLabel, fileSubtext, area);
            }
        });

        // Change event untuk input file
        fileInput.addEventListener('change', (e) => {
            if (fileInput.files.length) {
                handleFileSelection(fileInput.files[0], fileInput, fileLabel, fileSubtext, area);
            }
        });
    });
}

// Handle file selection
function handleFileSelection(file, fileInput, fileLabel, fileSubtext, area) {
    // Validasi file size (5MB max)
    const maxSize = 5 * 1024 * 1024;
    if (file.size > maxSize) {
        showToast('File terlalu besar! Maksimal 5MB.', 'danger');
        return;
    }

    // Validasi file type
    const allowedTypes = ['image/png', 'image/jpeg', 'image/jpg'];
    if (!allowedTypes.includes(file.type)) {
        showToast('Format file tidak didukung! Gunakan PNG, JPG, atau JPEG.', 'danger');
        return;
    }

    // Update UI
    updateFileLabel(fileLabel, fileSubtext, file);

    // Preview gambar jika area ini untuk gambar
    if (fileInput.accept.includes('image')) {
        previewImage(file, area);
    }

    showToast('File berhasil dipilih: ' + file.name, 'success');
}

// Update label file
function updateFileLabel(fileLabel, fileSubtext, file) {
    const fileName = file.name.length > 30 ? file.name.substring(0, 30) + '...' : file.name;
    fileLabel.innerHTML = `<i class="fas fa-check-circle text-success me-2"></i> ${fileName}`;
    fileSubtext.textContent = `Size: ${formatFileSize(file.size)} | Type: ${file.type}`;
    fileLabel.classList.add('text-success');
}

// Format ukuran file
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Preview gambar
function previewImage(file, container) {
    const existingPreview = container.querySelector('.preview-image');
    if (existingPreview) {
        existingPreview.remove();
    }

    if (file && file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.onload = function (e) {
            const img = document.createElement('img');
            img.src = e.target.result;
            img.classList.add('preview-image', 'img-fluid', 'mt-3');
            container.appendChild(img);
        };
        reader.readAsDataURL(file);
    }
}

// Fungsi untuk copy text ke clipboard
function copyToClipboard(text) {
    // Buat temporary textarea
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();

    try {
        const successful = document.execCommand('copy');
        document.body.removeChild(textArea);
        if (successful) {
            showToast('Text berhasil disalin!', 'success');
        } else {
            showToast('Gagal menyalin text!', 'danger');
        }
    } catch (err) {
        document.body.removeChild(textArea);
        // Fallback untuk browser modern
        navigator.clipboard.writeText(text).then(() => {
            showToast('Text berhasil disalin!', 'success');
        }).catch(() => {
            showToast('Gagal menyalin text!', 'danger');
        });
    }
}

// Show toast notification
function showToast(message, type = 'info') {
    // Buat toast element
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = `alert alert-${type} alert-dismissible fade show`;
    toast.style.position = 'fixed';
    toast.style.top = '20px';
    toast.style.right = '20px';
    toast.style.zIndex = '9999';
    toast.style.minWidth = '300px';
    toast.style.maxWidth = '400px';
    toast.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="fas ${getToastIcon(type)} me-2"></i>
            <div>${message}</div>
        </div>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
    `;

    document.body.appendChild(toast);

    // Auto remove setelah 4 detik
    setTimeout(() => {
        const toastElement = document.getElementById(toastId);
        if (toastElement) {
            toastElement.remove();
        }
    }, 4000);
}

function getToastIcon(type) {
    const icons = {
        'success': 'fa-check-circle',
        'danger': 'fa-exclamation-circle',
        'warning': 'fa-exclamation-triangle',
        'info': 'fa-info-circle'
    };
    return icons[type] || 'fa-info-circle';
}

// Fungsi untuk generate random key
function generateRandomKey(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Auto-generate Vigenere key
function setupKeyGeneration() {
    const generateKeyBtn = document.getElementById('generateKeyBtn');
    const vigenereKeyInput = document.getElementById('vigenere_key');

    if (generateKeyBtn && vigenereKeyInput) {
        generateKeyBtn.addEventListener('click', () => {
            vigenereKeyInput.value = generateRandomKey(8);
            showToast('Kunci berhasil digenerate!', 'success');
        });
    }
}

// Validasi form
function setupFormValidation() {
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        form.addEventListener('submit', (e) => {
            const requiredInputs = form.querySelectorAll('[required]');
            let isValid = true;

            requiredInputs.forEach(input => {
                if (!input.value.trim()) {
                    isValid = false;
                    input.classList.add('is-invalid');

                    // Add error message
                    if (!input.nextElementSibling || !input.nextElementSibling.classList.contains('invalid-feedback')) {
                        const errorDiv = document.createElement('div');
                        errorDiv.className = 'invalid-feedback';
                        errorDiv.textContent = 'Field ini wajib diisi!';
                        input.parentNode.appendChild(errorDiv);
                    }
                } else {
                    input.classList.remove('is-invalid');
                    const errorDiv = input.nextElementSibling;
                    if (errorDiv && errorDiv.classList.contains('invalid-feedback')) {
                        errorDiv.remove();
                    }
                }
            });

            if (!isValid) {
                e.preventDefault();
                showToast('Harap isi semua field yang wajib!', 'danger');
            }
        });
    });
}

// Toggle password visibility
function setupPasswordToggle() {
    const toggleButtons = document.querySelectorAll('.password-toggle');

    toggleButtons.forEach(button => {
        button.addEventListener('click', () => {
            const input = button.previousElementSibling;
            const icon = button.querySelector('i');

            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    });
}

// Animasi loading untuk form submit
function setupLoadingButtons() {
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        form.addEventListener('submit', function (e) {
            const submitButtons = this.querySelectorAll('button[type="submit"]');
            submitButtons.forEach(button => {
                const originalText = button.innerHTML;
                button.innerHTML = '<span class="loading-spinner me-2"></span> Memproses...';
                button.disabled = true;

                // Reset setelah 10 detik (fallback)
                setTimeout(() => {
                    button.innerHTML = originalText;
                    button.disabled = false;
                }, 10000);
            });
        });
    });
}

// Auto-hide alerts setelah 5 detik
function autoHideAlerts() {
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            if (alert.parentNode) {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        }, 5000);
    });
}

// File: static/js/script.js - Update fungsi validasi
function setupFileEncryptionForms() {
    const encryptForm = document.getElementById('encryptForm');
    const decryptForm = document.getElementById('decryptForm');

    if (encryptForm) {
        encryptForm.addEventListener('submit', function (e) {
            const fileInput = document.getElementById('encryptFileInput');
            if (!fileInput.files.length) {
                e.preventDefault();
                showToast('Pilih file yang akan dienkripsi!', 'danger');
                return false;
            }

            // Validasi ukuran file untuk RSA
            const file = fileInput.files[0];
            const maxRsaSize = 53; // 53 bytes untuk RSA 512-bit
            if (file.size > maxRsaSize) {
                e.preventDefault();
                showToast(`File terlalu besar untuk RSA! Maksimal ${maxRsaSize} bytes.`, 'danger');
                return false;
            }

            if (file.size === 0) {
                e.preventDefault();
                showToast('File kosong! Pilih file yang berisi data.', 'danger');
                return false;
            }
        });
    }

    if (decryptForm) {
        decryptForm.addEventListener('submit', function (e) {
            const fileInput = document.getElementById('decryptFileInput');
            const keyInput = document.getElementById('keyFileInput');

            if (!fileInput.files.length || !keyInput.files.length) {
                e.preventDefault();
                showToast('Pilih file terenkripsi dan kunci private!', 'danger');
                return false;
            }
        });
    }
}

function setupCopyButtons() {
    document.addEventListener('click', function (e) {
        if (e.target.classList.contains('copy-btn') || e.target.closest('.copy-btn')) {
            const button = e.target.classList.contains('copy-btn') ? e.target : e.target.closest('.copy-btn');
            const targetId = button.getAttribute('data-copy-target');

            if (targetId) {
                const targetElement = document.getElementById(targetId);
                if (targetElement) {
                    const textToCopy = targetElement.textContent || targetElement.value;
                    if (textToCopy.trim()) {
                        copyToClipboard(textToCopy.trim());
                    } else {
                        showToast('Tidak ada text untuk disalin!', 'warning');
                    }
                }
            }
        }
    });
}

function setupSteganographyMethods() {
    const methodSelect = document.getElementById('method');
    const descriptionSpan = document.getElementById('methodDescription');

    const descriptions = {
        'lsb_random': 'LSB Random: Modifikasi pixel secara acak menggunakan seed - KEAMANAN TINGGI, sulit dideteksi, kapasitas sedang',
        'eof': 'End of File (EOF): Menyembunyikan pesan di akhir file gambar - KAPASITAS TINGGI, mudah digunakan, kompatibel semua format'
    };

    if (methodSelect && descriptionSpan) {
        methodSelect.addEventListener('change', function () {
            descriptionSpan.textContent = descriptions[this.value] || '';
        });
        // Trigger initial description
        methodSelect.dispatchEvent(new Event('change'));
    }
}

// Initialize semua fungsi ketika DOM ready
document.addEventListener('DOMContentLoaded', function () {
    initializeFileUpload();
    setupKeyGeneration();
    setupFormValidation();
    setupPasswordToggle();
    setupLoadingButtons();
    setupFileEncryptionForms();
    setupSteganographyMethods();
    setupCopyButtons();
    autoHideAlerts();

    // Add animation class to elements
    const animatedElements = document.querySelectorAll('.card, .feature-box, .stat-card');
    animatedElements.forEach((element, index) => {
        element.classList.add('fade-in-up');
        element.style.animationDelay = `${index * 0.1}s`;
    });

    // Setup copy buttons
    const copyButtons = document.querySelectorAll('.copy-btn');
    copyButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetId = button.getAttribute('data-copy-target');
            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                copyToClipboard(targetElement.textContent || targetElement.value);
            }
        });
    });

    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function () {
            this.classList.add('loading-state');
        });
    });

    // Real-time character counter
    const textAreas = document.querySelectorAll('textarea[data-max-length]');
    textAreas.forEach(textarea => {
        const maxLength = parseInt(textarea.getAttribute('data-max-length'));
        const counter = document.createElement('div');
        counter.className = 'form-text text-end mt-1';
        counter.textContent = `0/${maxLength}`;
        textarea.parentNode.appendChild(counter);

        textarea.addEventListener('input', () => {
            const currentLength = textarea.value.length;
            counter.textContent = `${currentLength}/${maxLength}`;

            if (currentLength > maxLength) {
                counter.classList.add('text-danger');
                textarea.classList.add('is-invalid');
            } else {
                counter.classList.remove('text-danger');
                textarea.classList.remove('is-invalid');
            }
        });
    });

    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});

// Error handling untuk AJAX requests
window.addEventListener('error', function (e) {
    console.error('Error:', e.error);
    showToast('Terjadi kesalahan! Silakan refresh halaman.', 'danger');
});

// Handle page visibility changes
document.addEventListener('visibilitychange', function () {
    if (!document.hidden) {
        // Page is visible again, refresh any dynamic content if needed
        console.log('Page is now visible');
    }
});