# app.py
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os
from app import APK_Analyser
import logging
import numpy as np
import json

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB max file size

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure logging
logging.basicConfig(filename='apk_analyzer.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# Initialize the APK_Analyser
analyser = APK_Analyser()
model_path = "apk_malware.model"

# Custom JSON encoder to handle NumPy types
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.bool_):
            return bool(obj)
        return super(NumpyEncoder, self).default(obj)

app.json_encoder = NumpyEncoder

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and file.filename.endswith('.apk'):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            logging.info(f"Analyzing APK: {filename}")
            result, apk_data = analyser.identify(file_path, model_path)
            is_malware = bool(result == 1)  # Convert to Python boolean
            
            # Log the analysis result
            log_message = f"APK: {filename}, Is Malware: {is_malware}, Package: {apk_data['package']}"
            if is_malware:
                logging.warning(log_message)
            else:
                logging.info(log_message)
            
            return jsonify({
                'filename': filename,
                'is_malware': is_malware,
                'package_name': apk_data['package_name'],
                'package': apk_data['package'],
                'permissions': apk_data['permissions'],
                'activities': apk_data['activities'],
                'android_version': apk_data['android_version_name'],
            })
        except Exception as e:
            logging.error(f"Error analyzing APK {filename}: {str(e)}")
            return jsonify({'error': str(e)}), 500
        finally:
            # Clean up the uploaded file
            os.remove(file_path)
    else:
        return jsonify({'error': 'Invalid file type. Please upload an APK file.'}), 400

@app.route('/logs')
def view_logs():
    try:
        with open('apk_analyzer.log', 'r') as log_file:
            logs = log_file.readlines()
        return render_template('logs.html', logs=logs)
    except FileNotFoundError:
        return "Log file not found", 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5080)