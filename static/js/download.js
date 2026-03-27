// Download Manager - Handles file decryption and download

var DownloadManager = {
    fileId: null,
    csrfToken: null,
    
    init: function() {
        this.bindEvents();
        this.csrfToken = this.getCsrfToken();
    },
    
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
    
    bindEvents: function() {
        var btn = document.getElementById('downloadBtn');
        if (btn) {
            this.fileId = btn.getAttribute('data-file-id');
            btn.addEventListener('click', this.startDownload.bind(this));
        }
    },
    
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
    
    startDownload: function() {
        var self = this;
        var downloadBtn = document.getElementById('downloadBtn');
        var decryptionStatus = document.getElementById('decryptionStatus');
        var successMessage = document.getElementById('successMessage');
        var errorMessage = document.getElementById('errorMessage');
        
        if (downloadBtn) {
            downloadBtn.disabled = true;
            downloadBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Decrypting...';
        }
        if (errorMessage) {
            errorMessage.style.display = 'none';
        }
        
        // Step 1: Get encrypted file data from server
        this.updateProgress(1, 33);
        
        fetch('/files/' + this.fileId + '/download/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': this.csrfToken,
                'Content-Type': 'application/json'
            }
        })
        .then(function(response) {
            if (!response.ok) {
                throw new Error('Failed to retrieve file from server');
            }
            return response.json();
        })
        .then(function(data) {
            if (data.error) {
                throw new Error(data.error);
            }
            
            // Step 2: Decrypt AES key
            self.updateProgress(2, 66);
            
            return self.decryptAesKeyWithRSA(data.encrypted_aes_key, data.private_key)
                .then(function(decryptedAesKey) {
                    // Step 3: Decrypt file
                    self.updateProgress(3, 100);
                    
                    var encryptedData = self.base64ToArrayBuffer(data.file_data);
                    return self.decryptWithAES(encryptedData, decryptedAesKey, self.base64ToArrayBuffer(data.iv))
                        .then(function(decryptedData) {
                            return { fileName: data.file_name, data: decryptedData };
                        });
                });
        })
        .then(function(result) {
            // Create download
            var blob = new Blob([result.data]);
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = result.fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            if (decryptionStatus) {
                decryptionStatus.style.display = 'none';
            }
            if (downloadBtn) {
                downloadBtn.style.display = 'none';
            }
            if (successMessage) {
                successMessage.style.display = 'block';
            }
        })
        .catch(function(error) {
            if (decryptionStatus) {
                decryptionStatus.style.display = 'none';
            }
            if (errorMessage) {
                errorMessage.textContent = 'Error: ' + error.message;
                errorMessage.style.display = 'block';
            }
            if (downloadBtn) {
                downloadBtn.disabled = false;
                downloadBtn.innerHTML = '<i class="bi bi-download me-2"></i>Decrypt & Download';
            }
        });
    },
    
    decryptAesKeyWithRSA: function(encryptedAesKeyB64, privateKeyPem) {
        var self = this;
        return crypto.subtle.importKey(
            'pkcs8',
            this.pemToArrayBuffer(privateKeyPem),
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['decrypt']
        ).then(function(privateKey) {
            var encryptedAesKey = self.base64ToArrayBuffer(encryptedAesKeyB64);
            return crypto.subtle.decrypt(
                { name: 'RSA-OAEP' },
                privateKey,
                encryptedAesKey
            );
        }).then(function(decrypted) {
            return new Uint8Array(decrypted);
        });
    },
    
    decryptWithAES: function(encryptedData, key, iv) {
        return crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-CBC' },
            false,
            ['decrypt']
        ).then(function(cryptoKey) {
            return crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: iv },
                cryptoKey,
                encryptedData
            );
        });
    },
    
    pemToArrayBuffer: function(pem) {
        var b64 = pem.replace(/-----BEGIN.*?-----/g, '').replace(/-----END.*?-----/g, '').replace(/\s/g, '');
        var binary = atob(b64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },
    
    base64ToArrayBuffer: function(base64) {
        var binary = atob(base64);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
};

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    DownloadManager.init();
});

