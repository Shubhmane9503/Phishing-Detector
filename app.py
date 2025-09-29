from flask import Flask, request, jsonify, render_template_string, send_from_directory
from flask_cors import CORS
import json
import os
from dataclasses import asdict
import logging

# Import our phishing detector (assuming it's in the same directory)
from phishing_detector import PhishingDetector

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize the phishing detector
detector = PhishingDetector()

# HTML template for the web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Email Detection Agent</title>
    <style>
        /* Include the same CSS from the HTML artifact here */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #ff6b6b, #ee5a52);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        .content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            padding: 30px;
        }

        .input-section, .result-section {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
        }

        .section-title {
            font-size: 1.5em;
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            font-weight: 600;
            color: #555;
            margin-bottom: 8px;
        }

        input[type="text"], input[type="email"], textarea {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 14px;
            transition: all 0.3s ease;
        }

        textarea {
            resize: vertical;
            min-height: 120px;
        }

        .analyze-btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 15px 30px;
            font-size: 16px;
            font-weight: 600;
            border-radius: 10px;
            cursor: pointer;
            width: 100%;
            transition: all 0.3s ease;
        }

        .risk-level {
            font-size: 1.3em;
            font-weight: bold;
            padding: 10px 20px;
            border-radius: 25px;
            text-align: center;
            margin-bottom: 15px;
            text-transform: uppercase;
        }

        .risk-high { background: #ff4757; color: white; }
        .risk-medium { background: #ffa502; color: white; }
        .risk-low { background: #ffdd59; color: #333; }
        .risk-safe { background: #2ed573; color: white; }

        .quick-test-btn {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Phishing Email Detection Agent</h1>
            <p>Real-time AI-powered email security analysis</p>
        </div>

        <div class="content">
            <div class="input-section">
                <h2 class="section-title">📧 Email Analysis</h2>
                
                <form id="emailForm">
                    <div class="form-group">
                        <label for="sender">Sender Email:</label>
                        <input type="email" id="sender" placeholder="sender@example.com" required>
                    </div>

                    <div class="form-group">
                        <label for="subject">Subject Line:</label>
                        <input type="text" id="subject" placeholder="Email subject" required>
                    </div>

                    <div class="form-group">
                        <label for="content">Email Content:</label>
                        <textarea id="content" placeholder="Paste email content here..." required></textarea>
                    </div>

                    <div class="form-group">
                        <label for="attachments">Attachments (comma-separated):</label>
                        <input type="text" id="attachments" placeholder="document.pdf, image.jpg">
                    </div>

                    <button type="submit" class="analyze-btn">🔍 Analyze Email</button>
                </form>

                <div style="margin-top: 20px;">
                    <h4>🚀 Quick Tests:</h4>
                    <button class="quick-test-btn" onclick="loadSample('phishing')">Phishing Sample</button>
                    <button class="quick-test-btn" onclick="loadSample('legitimate')">Legitimate Sample</button>
                </div>
            </div>

            <div class="result-section">
                <h2 class="section-title">📊 Analysis Results</h2>
                <div id="results">
                    <p style="text-align: center; padding: 40px; color: #666;">
                        👆 Enter email details and click "Analyze Email" to see results
                    </p>
                </div>
            </div>
        </div>
    </div>

    <script>
        const samples = {
            phishing: {
                sender: "security@paypaI.com",
                subject: "URGENT: Account Suspended - Act Now!",
                content: "Dear Customer,\\n\\nYour PayPal account has been SUSPENDED due to suspicious activity!\\n\\nClick here immediately: http://bit.ly/paypal-verify\\n\\nYou have 24 hours to confirm or account will be closed.\\n\\nPayPal Security Team",
                attachments: "verification.exe"
            },
            legitimate: {
                sender: "notifications@amazon.com", 
                subject: "Your Order Confirmation",
                content: "Thank you for your purchase.\\n\\nOrder #123456 will ship in 2-3 days.\\n\\nTrack: https://amazon.com/track/123456\\n\\nAmazon Customer Service",
                attachments: ""
            }
        };

        function loadSample(type) {
            const sample = samples[type];
            document.getElementById('sender').value = sample.sender;
            document.getElementById('subject').value = sample.subject;
            document.getElementById('content').value = sample.content;
            document.getElementById('attachments').value = sample.attachments;
        }

        document.getElementById('emailForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = {
                sender: document.getElementById('sender').value,
                subject: document.getElementById('subject').value,
                content: document.getElementById('content').value,
                attachments: document.getElementById('attachments').value.split(',').map(s => s.trim()).filter(s => s)
            };

            document.getElementById('results').innerHTML = '<p style="text-align: center;">🔄 Analyzing...</p>';

            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });

                const result = await response.json();
                
                if (result.error) {
                    throw new Error(result.error);
                }

                displayResults(result);
            } catch (error) {
                document.getElementById('results').innerHTML = 
                    `<div style="background: #ff4757; color: white; padding: 15px; border-radius: 10px;">
                        <h3>Error</h3><p>${error.message}</p>
                    </div>`;
            }
        });

        function displayResults(result) {
            const indicators = result.indicators || [];
            
            document.getElementById('results').innerHTML = `
                <div style="background: #f8f9fa; border-radius: 10px; padding: 20px;">
                    <div class="risk-level risk-${result.risk_level.toLowerCase()}">
                        ${result.risk_level} RISK
                    </div>
                    
                    <div style="font-size: 2em; font-weight: bold; text-align: center; margin: 15px 0;">
                        Score: ${result.total_score}/20
                    </div>
                    
                    <div style="background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 15px; border-radius: 10px; text-align: center; font-weight: 600;">
                        ${getRecommendation(result.risk_level)}
                    </div>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 20px;">
                        <div style="background: white; padding: 15px; border-radius: 10px; border-left: 4px solid #667eea;">
                            <h4>📧 Sender</h4>
                            <div style="font-size: 1.5em; font-weight: bold; color: #667eea;">
                                ${result.sender_analysis?.score || 0} pts
                            </div>
                        </div>
                        <div style="background: white; padding: 15px; border-radius: 10px; border-left: 4px solid #667eea;">
                            <h4>🔗 URLs</h4>
                            <div style="font-size: 1.5em; font-weight: bold; color: #667eea;">
                                ${result.url_analysis?.score || 0} pts
                            </div>
                        </div>
                        <div style="background: white; padding: 15px; border-radius: 10px; border-left: 4px solid #667eea;">
                            <h4>📝 Content</h4>
                            <div style="font-size: 1.5em; font-weight: bold; color: #667eea;">
                                ${result.content_analysis?.score || 0} pts
                            </div>
                        </div>
                        <div style="background: white; padding: 15px; border-radius: 10px; border-left: 4px solid #667eea;">
                            <h4>📎 Attachments</h4>
                            <div style="font-size: 1.5em; font-weight: bold; color: #667eea;">
                                ${result.attachment_analysis?.score || 0} pts
                            </div>
                        </div>
                    </div>
                    
                    ${indicators.length > 0 ? `
                        <div style="background: white; border-radius: 10px; padding: 15px; margin-top: 15px;">
                            <h4>🚨 Risk Indicators:</h4>
                            ${indicators.map(indicator => 
                                `<span style="background: #e74c3c; color: white; padding: 5px 10px; margin: 3px; border-radius: 15px; display: inline-block; font-size: 0.9em;">${indicator}</span>`
                            ).join('')}
                        </div>
                    ` : '<div style="background: white; border-radius: 10px; padding: 15px; margin-top: 15px;"><h4>✅ No risk indicators found</h4></div>'}
                </div>
            `;
        }

        function getRecommendation(riskLevel) {
            switch(riskLevel) {
                case 'HIGH': return '⚠️ QUARANTINE EMAIL IMMEDIATELY';
                case 'MEDIUM': return '⚡ FLAG FOR REVIEW';
                case 'LOW': return '💡 MONITOR CLOSELY';
                default: return '✅ SAFE TO DELIVER';
            }
        }

        // Load sample on page load
        window.addEventListener('load', () => loadSample('phishing'));
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Serve the main web interface"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/analyze', methods=['POST'])
def analyze_email():
    """API endpoint to analyze an email for phishing indicators"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract email components
        sender = data.get('sender', '')
        subject = data.get('subject', '')
        content = data.get('content', '')
        attachments = data.get('attachments', [])
        
        # Validate required fields
        if not all([sender, subject, content]):
            return jsonify({'error': 'Sender, subject, and content are required'}), 400
        
        # Analyze the email
        logger.info(f"Analyzing email from {sender} with subject: {subject[:50]}...")
        
        result = detector.analyze_email(
            email_content=content,
            sender=sender,
            subject=subject,
            attachments=attachments
        )
        
        # Convert to dictionary for JSON response
        result_dict = asdict(result)
        
        logger.info(f"Analysis complete. Risk level: {result.risk_level}, Score: {result.total_score}")
        
        return jsonify(result_dict)
        
    except Exception as e:
        logger.error(f"Error analyzing email: {str(e)}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Phishing Email Detection Agent',
        'version': '1.0.0'
    })

@app.route('/api/test', methods=['GET'])
def test_samples():
    """Get test email samples"""
    samples = {
        'phishing': {
            'sender': 'security@paypaI.com',
            'subject': 'URGENT: Account Suspended - Act Now!',
            'content': '''Dear Customer,

Your PayPal account has been SUSPENDED due to suspicious activity!

Click here immediately to verify your account: http://bit.ly/paypal-verify-urgent

You have 24 hours to confirm your identity or your account will be permanently closed.

Thank you,
PayPal Security Team''',
            'attachments': ['account_verification.exe']
        },
        'legitimate': {
            'sender': 'notifications@amazon.com',
            'subject': 'Your Order Confirmation',
            'content': '''Thank you for your recent purchase. Your order #123456 will be shipped within 2-3 business days.

Track your order: https://amazon.com/track/123456

Best regards,
Amazon Customer Service''',
            'attachments': []
        },
        'suspicious': {
            'sender': 'winner@lottery-international.biz',
            'subject': 'Congratulations! You have won $1,000,000!!!',
            'content': '''CONGRATULATIONS!!!

You have been selected as the WINNER of our International Lottery!

Prize Amount: $1,000,000 USD

To claim your prize, click here: http://tiny.cc/lottery-claim

You must respond within 48 hours!

International Lottery Commission''',
            'attachments': ['claim_form.zip']
        }
    }
    
    return jsonify(samples)

if __name__ == '__main__':
    port = 8080  # Changed from 5000 to avoid macOS AirPlay conflict
    print("🛡️ Starting Phishing Email Detection Agent...")
    print(f"📡 Server will be available at: http://localhost:{port}")
    print(f"🔗 API endpoint: http://localhost:{port}/api/analyze")
    print(f"🏥 Health check: http://localhost:{port}/api/health")
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=port)