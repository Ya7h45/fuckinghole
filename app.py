

import os
import zipfile
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple, Any
import gradio as gr
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import joblib
import tempfile
import shutil
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px

class APKAnalyzer:
    """Core APK Analysis Engine"""
    
    def __init__(self):
        self.suspicious_permissions = {
            'android.permission.SEND_SMS': 5,
            'android.permission.READ_SMS': 4,
            'android.permission.RECEIVE_SMS': 4,
            'android.permission.READ_CONTACTS': 3,
            'android.permission.CAMERA': 3,
            'android.permission.RECORD_AUDIO': 4,
            'android.permission.ACCESS_FINE_LOCATION': 2,
            'android.permission.READ_PHONE_STATE': 3,
            'android.permission.CALL_PHONE': 4,
            'android.permission.WRITE_EXTERNAL_STORAGE': 2,
            'android.permission.SYSTEM_ALERT_WINDOW': 5,
            'android.permission.BIND_DEVICE_ADMIN': 5,
            'android.permission.REQUEST_INSTALL_PACKAGES': 5
        }
        
        self.legitimate_banks = [
            'com.chase.sig.android',
            'com.bankofamerica.MyBankofAmerica',
            'com.wellsfargo.mobile.android.wellsfargomobile',
            'com.citi.citimobile',
            'com.usaa.mobile.android.usaa',
            'com.capitalone.bank',
            'com.ally.MobileBanking',
            'com.schwab.mobile',
            'com.tdbank.mobile',
            'com.regions.mobbanking'
        ]
        
        self.banking_keywords = [
            'bank', 'banking', 'finance', 'payment', 'wallet', 'money',
            'transfer', 'account', 'credit', 'debit', 'loan', 'mortgage'
        ]
        
        # Initialize ML models
        self._init_models()
    
    def _init_models(self):
        """Initialize machine learning models"""
        self.rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.tfidf = TfidfVectorizer(max_features=1000, stop_words='english')
        
        # Train with dummy data for demo (in production, use real dataset)
        self._train_dummy_models()
    
    def _train_dummy_models(self):
        """Train models with synthetic data for demonstration"""
        # Generate synthetic training data
        np.random.seed(42)
        
        # Features: [permission_count, suspicious_perms, package_similarity, cert_validity]
        legitimate_features = np.random.normal([15, 2, 0.1, 1], [5, 1, 0.1, 0], (100, 4))
        malicious_features = np.random.normal([25, 8, 0.8, 0], [8, 3, 0.2, 0], (50, 4))
        
        X_train = np.vstack([legitimate_features, malicious_features])
        y_train = np.hstack([np.zeros(100), np.ones(50)])
        
        # Ensure non-negative values
        X_train = np.abs(X_train)
        
        # Train models
        X_scaled = self.scaler.fit_transform(X_train)
        self.rf_classifier.fit(X_scaled, y_train)
        self.isolation_forest.fit(X_scaled)
    
    def extract_apk_info(self, apk_path: str) -> Dict[str, Any]:
        """Extract comprehensive information from APK file"""
        try:
            info = {
                'file_info': self._get_file_info(apk_path),
                'manifest_info': {},
                'permissions': [],
                'activities': [],
                'services': [],
                'receivers': [],
                'certificates': [],
                'files': [],
                'analysis_time': datetime.now().isoformat()
            }
            
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Get file list
                info['files'] = apk_zip.namelist()
                
                # Extract AndroidManifest.xml if exists
                if 'AndroidManifest.xml' in info['files']:
                    # In a real implementation, you'd use aapt or similar to decode binary XML
                    # For demo, we'll simulate manifest parsing
                    info['manifest_info'] = self._simulate_manifest_parsing(apk_path)
                
                # Check for suspicious files
                info['suspicious_files'] = self._detect_suspicious_files(info['files'])
                
                # Extract certificates info
                cert_files = [f for f in info['files'] if f.startswith('META-INF/') and f.endswith('.RSA')]
                info['certificates'] = [{'file': cert} for cert in cert_files]
            
            return info
            
        except Exception as e:
            return {'error': f"Failed to extract APK info: {str(e)}"}
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        stat_info = os.stat(file_path)
        
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        return {
            'filename': os.path.basename(file_path),
            'size': stat_info.st_size,
            'sha256': file_hash,
            'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat()
        }
    
    def _simulate_manifest_parsing(self, apk_path: str) -> Dict[str, Any]:
        """Simulate AndroidManifest.xml parsing (in real implementation, use proper APK parsing)"""
        # This simulates what you'd get from parsing the actual manifest
        filename = os.path.basename(apk_path).lower()
        
        # Simulate package name based on filename
        if any(bank in filename for bank in ['chase', 'bank', 'wells', 'citi']):
            package_name = f"com.{filename.split('.')[0]}.mobile"
        else:
            package_name = f"com.suspicious.{filename.split('.')[0]}"
        
        # Simulate permissions based on "banking" nature
        base_permissions = [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.WAKE_LOCK'
        ]
        
        if 'suspicious' in package_name or any(word in filename for word in ['fake', 'clone', 'mod']):
            # Add suspicious permissions for fake apps
            suspicious_perms = [
                'android.permission.SEND_SMS',
                'android.permission.READ_SMS',
                'android.permission.READ_CONTACTS',
                'android.permission.CAMERA',
                'android.permission.RECORD_AUDIO',
                'android.permission.SYSTEM_ALERT_WINDOW'
            ]
            base_permissions.extend(suspicious_perms)
        
        return {
            'package': package_name,
            'version_name': '1.0.0',
            'version_code': '1',
            'min_sdk': '21',
            'target_sdk': '30',
            'permissions': base_permissions,
            'activities': [f'{package_name}.MainActivity', f'{package_name}.LoginActivity'],
            'services': [f'{package_name}.BackgroundService']
        }
    
    def _detect_suspicious_files(self, files: List[str]) -> List[Dict[str, Any]]:
        """Detect suspicious files in APK"""
        suspicious = []
        
        for file in files:
            if any(pattern in file.lower() for pattern in [
                'payload', 'exploit', 'shell', 'backdoor', 'trojan',
                'keylog', 'stealer', 'malware'
            ]):
                suspicious.append({
                    'file': file,
                    'reason': 'Suspicious filename pattern',
                    'risk': 'high'
                })
            
            # Check for multiple DEX files (common in malware)
            if file.startswith('classes') and file.endswith('.dex') and file != 'classes.dex':
                suspicious.append({
                    'file': file,
                    'reason': 'Multiple DEX files detected',
                    'risk': 'medium'
                })
        
        return suspicious
    
    def analyze_permissions(self, permissions: List[str]) -> Dict[str, Any]:
        """Analyze app permissions for suspicious patterns"""
        analysis = {
            'total_permissions': len(permissions),
            'suspicious_permissions': [],
            'risk_score': 0,
            'risk_level': 'low'
        }
        
        for perm in permissions:
            if perm in self.suspicious_permissions:
                risk_value = self.suspicious_permissions[perm]
                analysis['suspicious_permissions'].append({
                    'permission': perm,
                    'risk_value': risk_value,
                    'description': self._get_permission_description(perm)
                })
                analysis['risk_score'] += risk_value
        
        # Determine risk level
        if analysis['risk_score'] >= 20:
            analysis['risk_level'] = 'critical'
        elif analysis['risk_score'] >= 15:
            analysis['risk_level'] = 'high'
        elif analysis['risk_score'] >= 10:
            analysis['risk_level'] = 'medium'
        else:
            analysis['risk_level'] = 'low'
        
        return analysis
    
    def _get_permission_description(self, permission: str) -> str:
        """Get human-readable description of permission"""
        descriptions = {
            'android.permission.SEND_SMS': 'Can send text messages (potential premium SMS fraud)',
            'android.permission.READ_SMS': 'Can read text messages (intercept OTP codes)',
            'android.permission.RECEIVE_SMS': 'Can receive text messages',
            'android.permission.READ_CONTACTS': 'Can access contact list',
            'android.permission.CAMERA': 'Can take photos and videos',
            'android.permission.RECORD_AUDIO': 'Can record audio',
            'android.permission.ACCESS_FINE_LOCATION': 'Can access precise location',
            'android.permission.READ_PHONE_STATE': 'Can read phone state and identity',
            'android.permission.CALL_PHONE': 'Can make phone calls',
            'android.permission.SYSTEM_ALERT_WINDOW': 'Can display over other apps (overlay attacks)',
            'android.permission.BIND_DEVICE_ADMIN': 'Can perform device admin operations',
            'android.permission.REQUEST_INSTALL_PACKAGES': 'Can install other apps'
        }
        return descriptions.get(permission, 'Unknown permission')
    
    def check_package_legitimacy(self, package_name: str) -> Dict[str, Any]:
        """Check if package name resembles legitimate banking apps"""
        analysis = {
            'is_known_legitimate': package_name in self.legitimate_banks,
            'similarity_to_legitimate': 0,
            'suspicious_patterns': [],
            'banking_related': any(keyword in package_name.lower() for keyword in self.banking_keywords)
        }
        
        # Check for suspicious patterns
        if re.search(r'\.fake\.|\.clone\.|\.mod\.', package_name):
            analysis['suspicious_patterns'].append('Contains suspicious keywords (fake, clone, mod)')
        
        if package_name.count('.') > 4:
            analysis['suspicious_patterns'].append('Unusually long package name')
        
        # Calculate similarity to known legitimate banks
        max_similarity = 0
        for legit_bank in self.legitimate_banks:
            similarity = self._calculate_string_similarity(package_name, legit_bank)
            max_similarity = max(max_similarity, similarity)
        
        analysis['similarity_to_legitimate'] = max_similarity
        
        if max_similarity > 0.8 and not analysis['is_known_legitimate']:
            analysis['suspicious_patterns'].append(f'High similarity to legitimate bank app ({max_similarity:.2f})')
        
        return analysis
    
    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings using Jaccard similarity"""
        set1 = set(str1.lower())
        set2 = set(str2.lower())
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0
    
    def ml_risk_assessment(self, apk_info: Dict[str, Any]) -> Dict[str, Any]:
        """Perform ML-based risk assessment"""
        try:
            # Extract features for ML model
            features = self._extract_ml_features(apk_info)
            features_scaled = self.scaler.transform([features])
            
            # Get predictions
            fraud_probability = self.rf_classifier.predict_proba(features_scaled)[0][1]
            anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
            is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
            
            return {
                'fraud_probability': float(fraud_probability),
                'anomaly_score': float(anomaly_score),
                'is_anomaly': bool(is_anomaly),
                'ml_risk_level': self._get_ml_risk_level(fraud_probability),
                'confidence': float(abs(fraud_probability - 0.5) * 2)  # Distance from uncertain (0.5)
            }
        
        except Exception as e:
            return {
                'error': f"ML analysis failed: {str(e)}",
                'fraud_probability': 0.5,
                'anomaly_score': 0.0,
                'is_anomaly': False,
                'ml_risk_level': 'unknown',
                'confidence': 0.0
            }
    
    def _extract_ml_features(self, apk_info: Dict[str, Any]) -> List[float]:
        """Extract numerical features for ML models"""
        manifest_info = apk_info.get('manifest_info', {})
        permissions = manifest_info.get('permissions', [])
        
        # Feature 1: Total permission count
        permission_count = len(permissions)
        
        # Feature 2: Suspicious permission count
        suspicious_perm_count = sum(1 for perm in permissions if perm in self.suspicious_permissions)
        
        # Feature 3: Package name similarity to legitimate banks
        package_name = manifest_info.get('package', '')
        max_similarity = max([
            self._calculate_string_similarity(package_name, bank) 
            for bank in self.legitimate_banks
        ], default=0)
        
        # Feature 4: Certificate validity (simplified)
        cert_validity = 1 if apk_info.get('certificates') else 0
        
        return [permission_count, suspicious_perm_count, max_similarity, cert_validity]
    
    def _get_ml_risk_level(self, fraud_probability: float) -> str:
        """Convert fraud probability to risk level"""
        if fraud_probability >= 0.8:
            return 'critical'
        elif fraud_probability >= 0.6:
            return 'high'
        elif fraud_probability >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def generate_report(self, apk_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        if 'error' in apk_info:
            return apk_info
        
        manifest_info = apk_info.get('manifest_info', {})
        permissions = manifest_info.get('permissions', [])
        package_name = manifest_info.get('package', '')
        
        # Perform all analyses
        permission_analysis = self.analyze_permissions(permissions)
        package_analysis = self.check_package_legitimacy(package_name)
        ml_analysis = self.ml_risk_assessment(apk_info)
        
        # Calculate overall risk score
        overall_risk = self._calculate_overall_risk(
            permission_analysis, package_analysis, ml_analysis
        )
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'file_info': apk_info['file_info'],
            'app_info': {
                'package_name': package_name,
                'version': manifest_info.get('version_name', 'Unknown'),
                'target_sdk': manifest_info.get('target_sdk', 'Unknown')
            },
            'permission_analysis': permission_analysis,
            'package_analysis': package_analysis,
            'ml_analysis': ml_analysis,
            'suspicious_files': apk_info.get('suspicious_files', []),
            'overall_risk': overall_risk,
            'recommendations': self._generate_recommendations(overall_risk)
        }
        
        return report
    
    def _calculate_overall_risk(self, perm_analysis: Dict, pkg_analysis: Dict, ml_analysis: Dict) -> Dict[str, Any]:
        """Calculate overall risk assessment"""
        # Weight different factors
        weights = {
            'permissions': 0.3,
            'package': 0.3,
            'ml': 0.4
        }
        
        # Convert risk levels to numerical scores
        risk_scores = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4,
            'unknown': 2
        }
        
        perm_score = risk_scores.get(perm_analysis['risk_level'], 2)
        pkg_score = 3 if pkg_analysis['suspicious_patterns'] else 1
        ml_score = risk_scores.get(ml_analysis['ml_risk_level'], 2)
        
        # Calculate weighted average
        weighted_score = (
            perm_score * weights['permissions'] +
            pkg_score * weights['package'] +
            ml_score * weights['ml']
        )
        
        # Convert back to risk level
        if weighted_score >= 3.5:
            risk_level = 'critical'
        elif weighted_score >= 2.5:
            risk_level = 'high'
        elif weighted_score >= 1.5:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'score': round(weighted_score, 2),
            'level': risk_level,
            'fraud_probability': ml_analysis.get('fraud_probability', 0.5),
            'confidence': ml_analysis.get('confidence', 0.0)
        }
    
    def _generate_recommendations(self, overall_risk: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        risk_level = overall_risk['level']
        
        if risk_level == 'critical':
            recommendations.extend([
                "🚨 CRITICAL: Do NOT install this application",
                "🚨 This app shows multiple indicators of malicious behavior",
                "🚨 Report this app to relevant authorities",
                "🚨 Scan your device for malware if already installed"
            ])
        elif risk_level == 'high':
            recommendations.extend([
                "⚠️  HIGH RISK: Avoid installing this application",
                "⚠️  Multiple suspicious characteristics detected",
                "⚠️  Verify app authenticity through official channels",
                "⚠️  Consider alternative legitimate banking apps"
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                "⚡ MEDIUM RISK: Exercise caution",
                "⚡ Verify app source and developer",
                "⚡ Check official app store reviews",
                "⚡ Monitor app behavior after installation"
            ])
        else:
            recommendations.extend([
                "✅ LOW RISK: App appears legitimate",
                "✅ Continue with normal security practices",
                "✅ Keep app updated from official sources"
            ])
        
        # General recommendations
        recommendations.extend([
            "📱 Always download banking apps from official app stores",
            "🔒 Enable two-factor authentication where available",
            "🔍 Regularly review app permissions",
            "📊 Monitor bank statements for suspicious activity"
        ])
        
        return recommendations

def create_visualizations(report: Dict[str, Any]) -> Tuple:
    """Create visualization charts for the analysis report"""
    
    # Risk Level Gauge Chart
    risk_score = report['overall_risk']['score']
    risk_level = report['overall_risk']['level']
    
    fig_gauge = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = risk_score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Overall Risk Score"},
        delta = {'reference': 2},
        gauge = {
            'axis': {'range': [None, 4]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 1], 'color': "lightgreen"},
                {'range': [1, 2], 'color': "yellow"},
                {'range': [2, 3], 'color': "orange"},
                {'range': [3, 4], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 3.5
            }
        }
    ))
    fig_gauge.update_layout(height=400)
    
    # Permission Analysis Chart
    perm_analysis = report['permission_analysis']
    suspicious_perms = perm_analysis['suspicious_permissions']
    
    if suspicious_perms:
        perm_names = [perm['permission'].split('.')[-1] for perm in suspicious_perms]
        perm_risks = [perm['risk_value'] for perm in suspicious_perms]
        
        fig_perms = px.bar(
            x=perm_risks,
            y=perm_names,
            orientation='h',
            title="Suspicious Permissions Risk Analysis",
            labels={'x': 'Risk Score', 'y': 'Permission'},
            color=perm_risks,
            color_continuous_scale='Reds'
        )
        fig_perms.update_layout(height=400)
    else:
        fig_perms = go.Figure()
        fig_perms.add_annotation(
            text="No suspicious permissions detected",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=16)
        )
        fig_perms.update_layout(height=400, title="Permission Analysis")
    
    # ML Analysis Visualization
    ml_analysis = report['ml_analysis']
    fraud_prob = ml_analysis.get('fraud_probability', 0)
    
    fig_ml = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = fraud_prob * 100,
        title = {'text': "ML Fraud Probability (%)"},
        gauge = {
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkred"},
            'steps': [
                {'range': [0, 25], 'color': "lightgreen"},
                {'range': [25, 50], 'color': "yellow"},
                {'range': [50, 75], 'color': "orange"},
                {'range': [75, 100], 'color': "red"}
            ]
        }
    ))
    fig_ml.update_layout(height=400)
    
    return fig_gauge, fig_perms, fig_ml

def analyze_apk(apk_file) -> Tuple:
    """Main analysis function for Gradio interface"""
    if apk_file is None:
        return "Please upload an APK file.", None, None, None, ""
    
    try:
        # Initialize analyzer
        analyzer = APKAnalyzer()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
            shutil.copy(apk_file.name, tmp_file.name)
            
            # Extract APK information
            apk_info = analyzer.extract_apk_info(tmp_file.name)
            
            # Generate comprehensive report
            report = analyzer.generate_report(apk_info)
            
            # Clean up
            os.unlink(tmp_file.name)
        
        if 'error' in report:
            return f"Analysis failed: {report['error']}", None, None, None, ""
        
        # Create visualizations
        fig_gauge, fig_perms, fig_ml = create_visualizations(report)
        
        # Format text report
        text_report = format_text_report(report)
        
        return text_report, fig_gauge, fig_perms, fig_ml, json.dumps(report, indent=2)
    
    except Exception as e:
        return f"Error during analysis: {str(e)}", None, None, None, ""

def format_text_report(report: Dict[str, Any]) -> str:
    """Format the analysis report as readable text"""
    output = []
    
    # Header
    output.append("🛡️  BANKING APK SECURITY ANALYSIS REPORT")
    output.append("=" * 50)
    output.append(f"Analysis Time: {report['timestamp']}")
    output.append(f"File: {report['file_info']['filename']}")
    output.append(f"SHA256: {report['file_info']['sha256'][:32]}...")
    output.append("")
    
    # Overall Risk Assessment
    overall_risk = report['overall_risk']
    risk_emoji = {
        'low': '✅',
        'medium': '⚡',
        'high': '⚠️ ',
        'critical': '🚨'
    }
    
    output.append(f"🎯 OVERALL RISK ASSESSMENT")
    output.append(f"Risk Level: {risk_emoji.get(overall_risk['level'], '❓')} {overall_risk['level'].upper()}")
    output.append(f"Risk Score: {overall_risk['score']}/4.0")
    output.append(f"Fraud Probability: {overall_risk['fraud_probability']:.1%}")
    output.append(f"Confidence: {overall_risk['confidence']:.1%}")
    output.append("")
    
    # App Information
    app_info = report['app_info']
    output.append("📱 APPLICATION INFORMATION")
    output.append(f"Package Name: {app_info['package_name']}")
    output.append(f"Version: {app_info['version']}")
    output.append(f"Target SDK: {app_info['target_sdk']}")
    output.append("")
    
    # Permission Analysis
    perm_analysis = report['permission_analysis']
    output.append("🔐 PERMISSION ANALYSIS")
    output.append(f"Total Permissions: {perm_analysis['total_permissions']}")
    output.append(f"Suspicious Permissions: {len(perm_analysis['suspicious_permissions'])}")
    output.append(f"Permission Risk Score: {perm_analysis['risk_score']}")
    
    if perm_analysis['suspicious_permissions']:
        output.append("\nSuspicious Permissions Detected:")
        for perm in perm_analysis['suspicious_permissions'][:5]:  # Top 5
            output.append(f"  • {perm['permission'].split('.')[-1]} (Risk: {perm['risk_value']})")
            output.append(f"    {perm['description']}")
    output.append("")
    
    # Package Analysis
    pkg_analysis = report['package_analysis']
    output.append("📦 PACKAGE ANALYSIS")
    output.append(f"Known Legitimate Bank: {'Yes' if pkg_analysis['is_known_legitimate'] else 'No'}")
    output.append(f"Banking Related: {'Yes' if pkg_analysis['banking_related'] else 'No'}")
    output.append(f"Similarity to Legitimate: {pkg_analysis['similarity_to_legitimate']:.2f}")
    
    if pkg_analysis['suspicious_patterns']:
        output.append("\nSuspicious Patterns:")
        for pattern in pkg_analysis['suspicious_patterns']:
            output.append(f"  ⚠️  {pattern}")
    output.append("")
    
    # ML Analysis
    ml_analysis = report['ml_analysis']
    output.append("🤖 MACHINE LEARNING ANALYSIS")
    output.append(f"ML Risk Level: {ml_analysis['ml_risk_level'].upper()}")
    output.append(f"Fraud Probability: {ml_analysis['fraud_probability']:.1%}")
    output.append(f"Anomaly Detected: {'Yes' if ml_analysis['is_anomaly'] else 'No'}")
    output.append(f"Anomaly Score: {ml_analysis['anomaly_score']:.3f}")
    output.append("")
    
    # Suspicious Files
    suspicious_files = report['suspicious_files']
    if suspicious_files:
        output.append("📁 SUSPICIOUS FILES DETECTED")
        for file_info in suspicious_files[:3]:  # Top 3
            output.append(f"  🚩 {file_info['file']}")
            output.append(f"     Reason: {file_info['reason']}")
            output.append(f"     Risk: {file_info['risk'].upper()}")
        output.append("")
    
    # Recommendations
    output.append("💡 SECURITY RECOMMENDATIONS")
    for i, rec in enumerate(report['recommendations'][:8], 1):  # Top 8
        output.append(f"{i}. {rec}")
    
    return "\n".join(output)

# Create Gradio Interface
def create_interface():
    """Create the Gradio web interface"""
    
    with gr.Blocks(title="Banking APK Fraud Detector", theme=gr.themes.Soft()) as demo:
        gr.Markdown("""
        # 🛡️ Banking APK Fraud Detection Engine
        
        **AI-Powered Multi-Layer Analysis for Detecting Fake Banking Applications**
        
        Upload an APK file to perform comprehensive security analysis including:
        - 🔐 Permission analysis and risk assessment
        - 📱 Package legitimacy verification  
        - 🤖 Machine learning fraud detection""")