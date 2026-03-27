// Encryption Manager - Handles client-side file encryption

var EncryptionManager = {
    selectedFile: null,
    publicKey: null,
    
    // Initialize with public key from server
    init: function(publicKey) {
        this.publicKey = publicKey;
        this.bindEvents();
    },
    
    // Bind file input events
    bindEvents: function() {
        var uploadArea = document.getElementById('uploadArea');
        var fileInput = document.getElementById('fileInput');
        var removeFile = document.getElementById('removeFile');
        var uploadBtn = document.getElementById('uploadBtn');
        
        if (uploadArea && fileInput) {
            uploadArea.addEventListener('click', function() {
                fileInput.click();
            });
            
            fileInput.addEventListener('change', function(e) {
                if (e.target.files.length > 0) {
                    EncryptionManager.handleFile(e.target.files[0]);
                }
            });
            
            // Drag and drop
            uploadArea.addEventListener('dragover', function(e) {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            
            uploadArea.addEventListener('dragleave', function() {
                uploadArea.classList.remove('dragover');
            });
            
            uploadArea.addEventListener('drop', function(e) {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                if (e.dataTransfer.files.length > 0) {
                    EncryptionManager.handleFile(e.dataTransfer.files[0]);
                }
            });
        }
        
        if (removeFile) {
            removeFile.addEventListener('click', function() {
                EncryptionManager.removeFile();
            });
        }
        
        if (uploadBtn) {
            uploadBtn.addEventListener('click', function() {
                EncryptionManager.encryptAndUpload();
            });
        }
    },
    
    // Handle file selection
    handleFile: function(file) {
        this.selectedFile = file;
        
        var uploadArea = document.getElementById('uploadArea');
        var fileInfo = document.getElementById('fileInfo');
        var fileName = document.getElementById('fileName');
        var fileSize = document.getElementById('fileSize');
        var uploadBtn = document.getElementById('uploadBtn');
        
        if (fileName) fileName.textContent = file.name;
        if (fileSize) fileSize.textContent = this.formatFileSize(file.size);
        
        if (uploadArea) uploadArea.style.display = 'none';
        if (fileInfo) fileInfo.style.display = 'block';
        if (uploadBtn) uploadBtn.disabled = false;
        
        // Reset states
        var encryptionProgress = document.getElementById('encryptionProgress');
        var successMessage = document.getElementById('successMessage');
        var errorMessage = document.getElementById('errorMessage');
        
        if (encryptionProgress) encryptionProgress.style.display = 'none';
        if (successMessage) successMessage.style.display = 'none';
        if (errorMessage) errorMessage.style.display = 'none';
    },
    
    // Remove selected file
    removeFile: function() {
        this.selectedFile = null;
        
        var uploadArea = document.getElementById('uploadArea');
        var fileInput = document.getElementById('fileInput');
        var fileInfo = document.getElementById('fileInfo');
        var uploadBtn = document.getElementById('uploadBtn');
        var encryptionProgress = document.getElementById('encryptionProgress');
        
        if (fileInput) fileInput.value = '';
        if (uploadArea) uploadArea.style.display = 'block';
        if (fileInfo) fileInfo.style.display = 'none';
        if (uploadBtn) uploadBtn.disabled = true;
        if (encryptionProgress) encryptionProgress.style.display = 'none';
    },
    
    // Format file size
    formatFileSize: function(bytes) {
        if (bytes === 0) return '0 Bytes';
        var k = 1024;
        var sizes = ['Bytes', 'KB', 'MB', 'GB'];
        var i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    
    // Update progress
    updateProgress: function(step, percent) {
        var statusEl = document.getElementById('step' + step + 'Status');
        var progressBar = document.getElementById('progressBar');
        
        if (statusEl) {
            statusEl.innerHTML = '<i class="bi bi-check-circle-fill text-success"></i>';
        }
        if (progressBar) {
            progressBar.style.width = percent + '%';
        }
    },
    
    // Encrypt and upload file
    encryptAndUpload: function() {
        var self = this;
        
        if (!this.selectedFile) return;
        
        var encryptionProgress = document.getElementById('encryptionProgress');
        var uploadBtn = document.getElementById('uploadBtn');
        var errorMessage = document.getElementById('errorMessage');
        
        if (encryptionProgress) encryptionProgress.style.display = 'block';
        if (uploadBtn) uploadBtn.disabled = true;
        if (errorMessage) errorMessage.style.display = 'none';
        
        // Step 1: Generate AES key
        this.updateProgress(1, 25);
        
        // Read file
        this.selectedFile.arrayBuffer().then(function(fileData) {
            // Generate random AES key and IV
            var aesKey = crypto.getRandomValues(new Uint8Array(32)); // 256-bit key
            var iv = crypto.getRandomValues(new Uint8Array(16)); // 128-bit IV
            
            // Step 2: Encrypt file with AES
            self.updateProgress(2, 50);
            
            return self.encryptWithAES(new Uint8Array(fileData), aesKey, iv).then(function(encryptedData) {
                // Step 3: Encrypt AES key with RSA
                self.updateProgress(3, 75);
                
                return self.encryptAesKeyWithRSA(aesKey, self.publicKey).then(function(encryptedAesKey) {
                    return {
                        encryptedData: self.arrayBufferToBase64(encryptedData),
                        encryptedAesKey: encryptedAesKey,
                        iv: self.arrayBufferToBase64(iv)
                    };
                });
            });
        })
        .then(function(encrypted) {
            // Step 4: Upload to server
            self.updateProgress(4, 100);
            
            var formData = new FormData();
            formData.append('file_data', encrypted.encryptedData);
            formData.append('file_name', Date.now() + '_' + self.selectedFile.name);
            formData.append('original_name', self.selectedFile.name);
            formData.append('encrypted_aes_key', encrypted.encryptedAesKey);
            formData.append('iv', encrypted.iv);
            formData.append('csrfmiddlewaretoken', self.getCsrfToken());
            
            return fetch('/upload/', {
                method: 'POST',
                body: formData
            });
        })
        .then(function(response) {
            return response.json();
        })
        .then(function(result) {
            if (result.success) {
                var fileInfo = document.getElementById('fileInfo');
                var encryptionProgress = document.getElementById('encryptionProgress');
                var successMessage = document.getElementById('successMessage');
                var uploadBtn = document.getElementById('uploadBtn');
                
                if (fileInfo) fileInfo.style.display = 'none';
                if (encryptionProgress) encryptionProgress.style.display = 'none';
                if (successMessage) successMessage.style.display = 'block';
                if (uploadBtn) uploadBtn.style.display = 'none';
            } else {
                throw new Error(result.error || 'Upload failed');
            }
        })
        .catch(function(error) {
            var encryptionProgress = document.getElementById('encryptionProgress');
            var errorMessage = document.getElementById('errorMessage');
            var uploadBtn = document.getElementById('uploadBtn');
            
            if (encryptionProgress) encryptionProgress.style.display = 'none';
            if (errorMessage) {
                errorMessage.textContent = 'Error: ' + error.message;
                errorMessage.style.display = 'block';
            }
            if (uploadBtn) {
                uploadBtn.disabled = false;
            }
        });
    },
    
    // Get CSRF token from cookie
    getCsrfToken: function() {
        var name = 'csrftoken';
        var cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            var cookies = document.cookie.split(';');
            for (var i = 0; i < cookies.length; i++) {
                var cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    },
    
    // AES encryption using Web Crypto API
    encryptWithAES: function(data, key, iv) {
        return crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-CBC' },
            false,
            ['encrypt']
        ).then(function(cryptoKey) {
            return crypto.subtle.encrypt(
                { name: 'AES-CBC', iv: iv },
                cryptoKey,
                data
            );
        });
    },
    
    // RSA encryption for AES key
    encryptAesKeyWithRSA: function(aesKey, publicKeyPem) {
        return crypto.subtle.importKey(
            'spki',
            this.pemToArrayBuffer(publicKeyPem),
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['encrypt']
        ).then(function(publicKey) {
            return crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                publicKey,
                aesKey
            );
        }).then(function(encrypted) {
            return this.arrayBufferToBase64(encrypted);
        }.bind(this));
    },
    
    // Helper: Convert PEM to ArrayBuffer
    pemToArrayBuffer: function(pem) {
        var b64 = pem.replace(/-----BEGIN.*?-----/g, '').replace(/-----END.*?-----/g, '').replace(/\s/g, '');
        var binary = atob(b64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },
    
    // Helper: Convert ArrayBuffer to Base64
    arrayBufferToBase64: function(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = '';
        for (var i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
};

