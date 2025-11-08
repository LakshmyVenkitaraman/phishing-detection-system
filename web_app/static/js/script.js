// URL Phishing Detection - Frontend JavaScript

// DOM Elements
const urlInput = document.getElementById('urlInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const resultsSection = document.getElementById('resultsSection');
const resultsContent = document.getElementById('resultsContent');
const exampleButtons = document.querySelectorAll('.btn-example');

// Event Listeners
analyzeBtn.addEventListener('click', analyzeURL);
urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        analyzeURL();
    }
});

exampleButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        urlInput.value = btn.getAttribute('data-url');
        analyzeURL();
    });
});

// Main Analysis Function
async function analyzeURL() {
    const url = urlInput.value.trim();
    
    if (!url) {
        showError('Please enter a URL');
        return;
    }
    
    // Show loading state
    setLoadingState(true);
    hideResults();
    
    try {
        const response = await fetch('/api/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayResults(data);
        } else {
            showError(data.error || 'An error occurred');
        }
    } catch (error) {
        console.error('Error:', error);
        showError('Failed to analyze URL. Please check if the server is running.');
    } finally {
        setLoadingState(false);
    }
}

// Display Results
function displayResults(data) {
    const { prediction, confidence, risk_score, url, features } = data;
    
    // Determine result class and icon
    let resultClass, resultIcon, resultMessage;
    
    if (prediction === 'legitimate') {
        resultClass = 'result-legitimate';
        resultIcon = '✓';
        resultMessage = 'This URL appears to be safe';
    } else if (prediction === 'phishing') {
        resultClass = 'result-phishing';
        resultIcon = '⚠️';
        resultMessage = 'Warning: Potential phishing attempt detected!';
    } else {
        resultClass = 'result-suspicious';
        resultIcon = '❓';
        resultMessage = 'This URL shows suspicious characteristics';
    }
    
    // Generate reasons based on features
    const reasons = generateReasons(features);
    
    // Convert confidence to percentage
    const confidencePercent = Math.round(confidence * 100);
    const riskPercent = Math.round(risk_score * 100);
    
    // Build HTML
    const html = `
        <div class="result-header ${resultClass}">
            <div class="result-info">
                <div class="result-icon">${resultIcon}</div>
                <div class="result-text">
                    <h3>${prediction.toUpperCase()}</h3>
                    <p>${resultMessage}</p>
                </div>
            </div>
            <div class="result-confidence">
                <div class="confidence-circle">
                    ${confidencePercent}%
                </div>
                <small>Confidence</small>
            </div>
        </div>
        
        <div class="result-url">
            <strong>Analyzed URL:</strong><br>
            ${escapeHtml(url)}
        </div>
        
        ${reasons.length > 0 ? `
            <div class="result-reasons">
                <h4>Detection Factors:</h4>
                ${reasons.map(reason => `
                    <div class="reason-item">
                        <span class="reason-icon">${reason.icon}</span>
                        <span>${reason.text}</span>
                    </div>
                `).join('')}
            </div>
        ` : ''}
        
        <div class="result-stats">
            <p><strong>Risk Score:</strong> ${riskPercent}%</p>
        </div>
    `;
    
    resultsContent.innerHTML = html;
    showResults();
}

// Generate Reasons from Features
function generateReasons(features) {
    const reasons = [];
    
    if (features.is_https === 0) {
        reasons.push({ 
            icon: '🔓', 
            text: 'Not using secure HTTPS protocol' 
        });
    }
    
    if (features.has_ip === 1) {
        reasons.push({ 
            icon: '🔢', 
            text: 'Domain contains IP address instead of domain name' 
        });
    }
    
    if (features.url_length > 75) {
        reasons.push({ 
            icon: '📏', 
            text: 'Unusually long URL' 
        });
    }
    
    if (features.has_suspicious_words === 1) {
        reasons.push({ 
            icon: '🔍', 
            text: 'Contains suspicious keywords (login, verify, account, etc.)' 
        });
    }
    
    if (features.num_subdomains > 2) {
        reasons.push({ 
            icon: '🌐', 
            text: 'Too many subdomains in the URL' 
        });
    }
    
    if (features.has_double_slash_redirect === 1) {
        reasons.push({ 
            icon: '↩️', 
            text: 'Contains redirects in the URL' 
        });
    }
    
    if (features.domain_has_digits > 4) {
        reasons.push({ 
            icon: '🔢', 
            text: 'Domain contains many digits' 
        });
    }
    
    if (features.has_random_pattern === 1) {
        reasons.push({ 
            icon: '🎲', 
            text: 'Random character pattern detected' 
        });
    }
    
    if (features.special_char_count > 15) {
        reasons.push({ 
            icon: '🔣', 
            text: 'High number of special characters' 
        });
    }
    
    return reasons.slice(0, 6); // Limit to 6 reasons
}

// Helper Functions
function setLoadingState(isLoading) {
    const btnText = analyzeBtn.querySelector('.btn-text');
    const btnLoader = analyzeBtn.querySelector('.btn-loader');
    
    if (isLoading) {
        btnText.style.display = 'none';
        btnLoader.style.display = 'block';
        analyzeBtn.disabled = true;
    } else {
        btnText.style.display = 'block';
        btnLoader.style.display = 'none';
        analyzeBtn.disabled = false;
    }
}

function showResults() {
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideResults() {
    resultsSection.style.display = 'none';
}

function showError(message) {
    resultsContent.innerHTML = `
        <div class="result-header result-phishing">
            <div class="result-info">
                <div class="result-icon">❌</div>
                <div class="result-text">
                    <h3>ERROR</h3>
                    <p>${escapeHtml(message)}</p>
                </div>
            </div>
        </div>
    `;
    showResults();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize
console.log('URL Phishing Detection System loaded');
console.log('Ready to analyze URLs!');
