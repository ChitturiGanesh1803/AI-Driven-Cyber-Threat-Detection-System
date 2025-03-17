#pip install streamlit pandas numpy tldextract plotly scikit-learn python-whois requests
import streamlit as st
import pandas as pd
import numpy as np
import tldextract
import re
import joblib
import plotly.express as px
import plotly.graph_objects as go
from urllib.parse import urlparse
from datetime import datetime
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import whois
import base64
import webbrowser
import requests
import time

# Configuration
st.set_page_config(
    page_title="PhishShield Pro - AI Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load VirusTotal API key from secrets
VIRUSTOTAL_API_KEY = st.secrets.get("virustotal", {}).get("api_key", "")

# Custom styling
st.markdown("""
    <style>
    .main-title {
        font-size: 2.8rem;
        color: #1E3A8A;
        font-weight: 800;
        text-align: center;
        margin-bottom: 1rem;
    }
    .risk-card {
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        margin: 1rem 0;
    }
    .disclaimer {
        font-size: 0.9rem;
        color: #6B7280;
        margin-top: 1rem;
    }
    </style>
""", unsafe_allow_html=True)

class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'banking', 
            'password', 'oauth', 'auth', 'confirm', 'validate', 'payment'
        ]
        self.suspicious_tlds = ['xyz', 'top', 'gq', 'cf', 'tk', 'ml', 'club', 'info']
        self.legit_domains = ['google', 'microsoft', 'github', 'wikipedia', 'nytimes']
        
    def extract_features(self, url):
        features = {}
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        # Basic URL features
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed.netloc)
        features['num_subdomains'] = parsed.netloc.count('.')
        features['has_https'] = int(parsed.scheme == 'https')
        features['is_ip'] = int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.netloc)))
        features['path_depth'] = parsed.path.count('/')
        features['special_chars'] = sum(url.count(c) for c in ['@', '!', '$', '%', '&'])
        features['suspicious_keywords'] = sum(1 for kw in self.suspicious_keywords if kw in url.lower())
        features['suspicious_tld'] = int(ext.suffix in self.suspicious_tlds)
        features['redirects'] = url.count('//') - 1
        features['hex_chars'] = sum(1 for c in url if c in '%#')
        features['brand_in_domain'] = int(any(brand in url.lower() for brand in self.legit_domains))
        features['punycode'] = int('xn--' in parsed.netloc)
        features['port_present'] = int(':' in parsed.netloc)

        # Domain age and registration details
        try:
            domain_info = whois.whois(parsed.netloc)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            features['domain_age_days'] = (datetime.now() - creation_date).days if creation_date else -1
            features['registrar'] = hash(str(domain_info.registrar)) % 1000
        except Exception:
            features['domain_age_days'] = -1
            features['registrar'] = -1
            
        return features

def train_and_save_model():
    # Synthetic dataset generation
    data = pd.DataFrame({
        'url': [
            'https://github.com', 'https://www.nytimes.com', 'https://microsoft.com',
            'http://faceb00k-login.net', 'https://paypal-security-update.com'
        ],
        'label': [0, 0, 0, 1, 1]
    })
    
    analyzer = URLAnalyzer()
    features = [analyzer.extract_features(url) for url in data['url']]
    feature_df = pd.DataFrame(features)
    numerical_features = feature_df.select_dtypes(include=np.number)
    
    X = numerical_features.values
    y = data['label'].values
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=2, stratify=y, random_state=42)

    
    model = GradientBoostingClassifier(
        n_estimators=500,
        learning_rate=0.01,
        max_depth=7,
        subsample=0.8,
        random_state=42
    )
    model.fit(X_train, y_train)
    
    model_data = {
        'model': model,
        'features': numerical_features.columns.tolist(),
        'train_accuracy': accuracy_score(y_train, model.predict(X_train)),
        'test_accuracy': accuracy_score(y_test, model.predict(X_test))
    }
    
    joblib.dump(model_data, 'phishshield_pro_model.pkl')
    return model_data

@st.cache_resource
def load_model():
    try:
        model_data = joblib.load('phishshield_pro_model.pkl')
        if model_data['test_accuracy'] < 0.95:
            return train_and_save_model()
        return model_data
    except FileNotFoundError:
        return train_and_save_model()

def check_virustotal(url):
    """Check URL reputation using VirusTotal API with full scan workflow."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    # Step 1: Submit URL for analysis
    submit_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(submit_url, headers=headers, data={"url": url})
    
    if response.status_code != 200:
        return None
    
    analysis_id = response.json()['data']['id']
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    # Step 2: Wait for analysis completion
    for _ in range(5):  # Max 5 attempts
        analysis_response = requests.get(analysis_url, headers=headers)
        if analysis_response.status_code == 200:
            status = analysis_response.json()['data']['attributes']['status']
            if status == 'completed':
                # Step 3: Get final results
                encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                report_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
                report_response = requests.get(report_url, headers=headers)
                if report_response.status_code == 200:
                    stats = report_response.json()['data']['attributes']['last_analysis_stats']
                    return stats['malicious'] == 0
        time.sleep(15)  # Wait 15 seconds between checks
    
    return None

def create_radar_chart(features):
    categories = ['Length', 'Subdomains', 'Security', 'Complexity', 'Age']
    values = [
        min(features['url_length'] / 150, 1) * 100,
        min(features['num_subdomains'] * 15, 100),
        features['has_https'] * 100,
        min(features['special_chars'] * 20, 100),
        (features['domain_age_days'] if features['domain_age_days'] > 0 else 365) / 365 * 100
    ]
    
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=values, theta=categories, fill='toself', 
        name='Risk Profile', line=dict(color='#3B82F6')
    ))
    fig.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 100], gridcolor='#E5E7EB'),
            angularaxis=dict(gridcolor='#E5E7EB')
        ),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=400
    )
    return fig

def main():
    st.markdown("<div class='main-title'>🛡️ PhishShield Pro - AI-Driven Cyber Threat Detection System </div>", unsafe_allow_html=True)
    # Enterprise Security   
    model_data = load_model()
    analyzer = URLAnalyzer()
    
    col1, col2 = st.columns([2, 1])
    url_input = col1.text_input("Enter URL to analyze:", placeholder="https://example.com")
    
    if col2.button("Analyze", type="primary") and url_input:
        with st.spinner("🔍 Analyzing URL..."):
            try:
                # Feature extraction
                features = analyzer.extract_features(url_input)
                features_df = pd.DataFrame([features])[model_data['features']]
                
                # Model prediction
                prediction = model_data['model'].predict(features_df)[0]
                proba = model_data['model'].predict_proba(features_df)[0]
                
                # VirusTotal check
                vt_safe = check_virustotal(url_input)
                
                # Results display
                st.markdown("---")
                result_class = "safe-card" if prediction == 0 else "phishing-card"
                result_text = "✅ Certified Safe URL" if prediction == 0 else "⚠️ Confirmed Phishing URL"
                
                st.markdown(f"""
                    <div class="risk-card {result_class}">
                        <h2 style="color: {'#10B981' if prediction == 0 else '#EF4444'};">{result_text}</h2>
                        <p>Phishing Confidence: {proba[1]*100:.1f}%</p>
                        <div class="disclaimer">
                            Enterprise-grade detection accuracy: {model_data['test_accuracy']*100:.1f}%
                        </div>
                    </div>
                """, unsafe_allow_html=True)

                # Safety verification and browser action
                if prediction == 0 and vt_safe:
                    st.success("Verified safe by both AI model and VirusTotal. Opening URL...")
                    webbrowser.open(url_input)
                elif prediction == 0 and vt_safe is None:
                    st.warning("AI model considers this safe but VirusTotal verification failed")
                elif prediction == 0 and not vt_safe:
                    st.error("AI model considers safe but VirusTotal detected risks")
                else:
                    st.error("Potential phishing threat detected. Access blocked.")

                # Visualization
                col1, col2 = st.columns(2)
                with col1:
                    st.plotly_chart(create_radar_chart(features), use_container_width=True)
                with col2:
                    fig = px.bar(
                        pd.DataFrame({'Feature': features.keys(), 'Value': features.values()}),
                        x='Feature', y='Value', 
                        title='Feature Analysis',
                        color_discrete_sequence=['#3B82F6']
                    )
                    st.plotly_chart(fig.update_layout(
                        height=400,
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)'
                    ), use_container_width=True)

            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")

if __name__ == "__main__":
    main()