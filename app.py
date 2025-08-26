"""
Enhanced Flask Web Application for AI-Powered Security Analysis
Supports automatic file type detection, archive extraction, and comprehensive analysis.
"""
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
from pathlib import Path
import pandas as pd
import os
import sys
import json
import logging
import uuid
import time
import zipfile
import tarfile
import rarfile
import shutil
import tempfile

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Get absolute paths
BASE_DIR = Path(__file__).parent
VAULT_DIR = BASE_DIR.parent if BASE_DIR.name != 'vault' else BASE_DIR
sys.path.append(str(VAULT_DIR))

# Import required modules from vault
try:
    from orchestrator import AnalysisOrchestrator
    from utils import setup_logging
    logger.info("Successfully imported analysis modules")
except ImportError as e:
    logger.error(f"Failed to import analysis modules: {e}")
    sys.exit(1)

app = Flask(__name__)

# Configure directories
app.config['UPLOAD_FOLDER'] = BASE_DIR / 'uploads'
app.config['RESULTS_FOLDER'] = VAULT_DIR / 'results'
app.config['TEMP_FOLDER'] = BASE_DIR / 'temp'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

# Create necessary directories
for folder in [app.config['UPLOAD_FOLDER'], app.config['RESULTS_FOLDER'], app.config['TEMP_FOLDER']]:
    folder.mkdir(exist_ok=True)

# Supported file extensions
ALLOWED_EXTENSIONS = {
    'code': {'zip', 'rar', 'tar', 'tar.gz', 'tgz'},
    'report': {'pdf', 'md', 'txt'},
    'all': {'zip', 'rar', 'tar', 'tar.gz', 'tgz', 'pdf', 'md', 'txt'}
}

def allowed_file(filename, file_type='all'):
    """Check if file extension is allowed."""
    if '.' not in filename:
        return False

    # Handle compound extensions like .tar.gz
    lower_filename = filename.lower()
    if lower_filename.endswith('.tar.gz') or lower_filename.endswith('.tar.bz2'):
        ext = lower_filename.split('.')[-2] + '.' + lower_filename.split('.')[-1]
    else:
        ext = lower_filename.rsplit('.', 1)[1]

    return ext in ALLOWED_EXTENSIONS.get(file_type, ALLOWED_EXTENSIONS['all'])

def extract_archive(archive_path, extract_to):
    """Extract various archive formats."""
    logger.info(f"Extracting {archive_path} to {extract_to}")

    try:
        if archive_path.suffix.lower() == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)

        elif archive_path.suffix.lower() == '.rar':
            with rarfile.RarFile(archive_path, 'r') as rar_ref:
                rar_ref.extractall(extract_to)

        elif archive_path.suffix.lower() in ['.tar', '.tgz'] or archive_path.name.endswith('.tar.gz'):
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                tar_ref.extractall(extract_to)

        else:
            raise ValueError(f"Unsupported archive format: {archive_path.suffix}")

        logger.info(f"Successfully extracted {archive_path}")
        return True

    except Exception as e:
        logger.error(f"Failed to extract {archive_path}: {e}")
        return False

def detect_file_type(filename):
    """Detect if file is report, code archive, or other."""
    ext = filename.lower().split('.')[-1]

    if ext in ALLOWED_EXTENSIONS['report']:
        return 'report'
    elif ext in ALLOWED_EXTENSIONS['code'] or filename.lower().endswith('.tar.gz'):
        return 'code'
    else:
        return 'unknown'

def setup_openrouter_env():
    """Setup OpenRouter environment variables with defaults."""
    # Set default OpenRouter configuration
    if not os.getenv('OPENROUTER_API_KEY'):
        logger.warning("OPENROUTER_API_KEY not set - LLM features will be disabled")

    # Set default model if not specified
    if not os.getenv('LLM_MODEL'):
        os.environ['LLM_MODEL'] = 'anthropic/claude-3.5-sonnet'

    # Set default max tokens
    if not os.getenv('LLM_MAX_TOKENS'):
        os.environ['LLM_MAX_TOKENS'] = '1500'

    logger.info(f"OpenRouter Config - Model: {os.getenv('LLM_MODEL')}, Max Tokens: {os.getenv('LLM_MAX_TOKENS')}")

@app.route('/')
def index():
    """Serve the main page."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle file upload and analysis."""
    try:
        logger.info("Starting analysis request")

        # Check if files were uploaded
        if not request.files:
            return jsonify({'error': 'No files uploaded'}), 400

        # Setup OpenRouter configuration
        setup_openrouter_env()

        # Create unique session directory
        session_id = uuid.uuid4().hex
        session_dir = app.config['TEMP_FOLDER'] / session_id
        session_dir.mkdir(exist_ok=True)

        uploaded_files = []
        report_path = None
        code_directory = None

        try:
            # Process all uploaded files
            for file_key in request.files:
                file = request.files[file_key]

                if file.filename == '':
                    continue

                if not allowed_file(file.filename):
                    logger.warning(f"File {file.filename} not allowed")
                    continue

                # Save uploaded file
                filename = secure_filename(file.filename)
                file_path = session_dir / filename
                file.save(str(file_path))

                file_type = detect_file_type(filename)
                uploaded_files.append({
                    'name': filename,
                    'path': file_path,
                    'type': file_type
                })

                logger.info(f"Uploaded {filename} (type: {file_type})")

            if not uploaded_files:
                return jsonify({'error': 'No valid files uploaded'}), 400

            # Process uploaded files
            for file_info in uploaded_files:
                if file_info['type'] == 'report':
                    report_path = str(file_info['path'])
                    logger.info(f"Report file: {report_path}")

                elif file_info['type'] == 'code':
                    # Extract code archive
                    extract_dir = session_dir / 'extracted_code'
                    extract_dir.mkdir(exist_ok=True)

                    if extract_archive(file_info['path'], extract_dir):
                        # Find the main directory in extracted files
                        extracted_items = list(extract_dir.iterdir())
                        if len(extracted_items) == 1 and extracted_items[0].is_dir():
                            code_directory = str(extracted_items[0])
                        else:
                            code_directory = str(extract_dir)

                        logger.info(f"Code directory: {code_directory}")
                    else:
                        return jsonify({'error': f'Failed to extract {file_info["name"]}'}), 500

            # Validate inputs
            if not report_path and not code_directory:
                return jsonify({'error': 'No valid report or code files found'}), 400

            # Run analysis
            logger.info("Starting comprehensive analysis")

            orchestrator = AnalysisOrchestrator(str(app.config['RESULTS_FOLDER']))

            # Run targeted analysis based on available inputs
            results = orchestrator.run_targeted_analysis(
                report_path=report_path,
                code_directory=code_directory,
                app_url=None,  # Web UI doesn't support URL input yet
                enable_sast=True,
                enable_dynamic=False,  # Disable dynamic analysis for web UI
                enable_llm=bool(os.getenv('OPENROUTER_API_KEY')),
                enable_export=True
            )

            logger.info("Analysis completed successfully")

            # Process and return results
            return process_analysis_results(results)

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return jsonify({
                'error': 'Analysis failed', 
                'details': str(e),
                'type': 'analysis_error'
            }), 500

        finally:
            # Cleanup session directory
            try:
                if session_dir.exists():
                    shutil.rmtree(session_dir)
                    logger.info("Cleaned up session directory")
            except Exception as e:
                logger.warning(f"Failed to cleanup session directory: {e}")

    except Exception as e:
        logger.error(f"Request failed: {e}")
        return jsonify({
            'error': 'Request processing failed', 
            'details': str(e),
            'type': 'request_error'
        }), 500

def process_analysis_results(analysis_results):
    """Process analysis results and return formatted response."""
    try:
        # Get latest result files
        result_files = list(app.config['RESULTS_FOLDER'].glob('analysis_results_*'))
        if not result_files:
            return jsonify({'error': 'No result files generated'}), 404

        # Get the most recent result set
        latest_timestamp = max(result_files, key=lambda x: x.stat().st_mtime).name.split('_')[2]

        # Find all files from the latest analysis
        latest_files = {
            'manifest': None,
            'endpoints': None,
            'vulnerabilities': None,
            'test_cases': None,
            'coverage': None,
            'summary': None
        }

        for result_file in result_files:
            if latest_timestamp in result_file.name:
                if 'manifest.json' in result_file.name:
                    latest_files['manifest'] = result_file
                elif 'endpoints.csv' in result_file.name:
                    latest_files['endpoints'] = result_file
                elif 'vulnerabilities.csv' in result_file.name:
                    latest_files['vulnerabilities'] = result_file
                elif 'test_cases.csv' in result_file.name:
                    latest_files['test_cases'] = result_file
                elif 'coverage.csv' in result_file.name:
                    latest_files['coverage'] = result_file
                elif 'summary.md' in result_file.name:
                    latest_files['summary'] = result_file

        # Process results
        processed_results = {
            'analysis_summary': {},
            'endpoints': [],
            'vulnerabilities': [], 
            'test_cases': [],
            'coverage': [],
            'files': {}
        }

        # Load manifest for summary
        if latest_files['manifest'] and latest_files['manifest'].exists():
            try:
                with open(latest_files['manifest'], 'r') as f:
                    manifest_data = json.load(f)
                    processed_results['analysis_summary'] = manifest_data.get('analysis_summary', {})
            except Exception as e:
                logger.warning(f"Could not load manifest: {e}")

        # Process CSV files
        csv_files = ['endpoints', 'vulnerabilities', 'test_cases', 'coverage']
        for file_type in csv_files:
            if latest_files[file_type] and latest_files[file_type].exists():
                try:
                    df = pd.read_csv(latest_files[file_type])
                    processed_results[file_type] = df.to_dict('records')
                    processed_results['files'][file_type] = {
                        'path': str(latest_files[file_type]),
                        'size': latest_files[file_type].stat().st_size,
                        'rows': len(df)
                    }
                    logger.info(f"Processed {file_type}: {len(df)} rows")
                except Exception as e:
                    logger.error(f"Error processing {file_type}: {e}")
                    processed_results[file_type] = []

        # Load summary markdown
        if latest_files['summary'] and latest_files['summary'].exists():
            try:
                with open(latest_files['summary'], 'r', encoding='utf-8') as f:
                    processed_results['summary_text'] = f.read()
            except Exception as e:
                logger.warning(f"Could not load summary: {e}")

        # Add metadata
        processed_results['metadata'] = {
            'timestamp': latest_timestamp,
            'total_files': len([f for f in latest_files.values() if f and f.exists()]),
            'analysis_date': time.strftime('%Y-%m-%d %H:%M:%S')
        }

        return jsonify({
            'status': 'success',
            'results': processed_results
        })

    except Exception as e:
        logger.error(f"Error processing results: {e}")
        return jsonify({
            'error': 'Failed to process analysis results',
            'details': str(e)
        }), 500

@app.route('/download/<file_type>')
def download_file(file_type):
    """Download result files."""
    try:
        # Get latest result files
        result_files = list(app.config['RESULTS_FOLDER'].glob(f'*{file_type}*'))
        if not result_files:
            return jsonify({'error': f'No {file_type} files found'}), 404

        latest_file = max(result_files, key=lambda x: x.stat().st_mtime)
        return send_file(latest_file, as_attachment=True)

    except Exception as e:
        logger.error(f"Download failed: {e}")
        return jsonify({'error': 'Download failed', 'details': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'version': '2.0.0',
        'openrouter_configured': bool(os.getenv('OPENROUTER_API_KEY')),
        'model': os.getenv('LLM_MODEL', 'not_set'),
        'max_tokens': os.getenv('LLM_MAX_TOKENS', 'not_set')
    })

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error."""
    return jsonify({'error': 'File too large. Maximum size is 50MB.'}), 413

if __name__ == '__main__':
    # Setup environment
    setup_openrouter_env()
    setup_logging()

    # Check dependencies
    missing_deps = []
    try:
        import rarfile
    except ImportError:
        missing_deps.append('rarfile')

    if missing_deps:
        logger.warning(f"Missing optional dependencies: {missing_deps}")
        logger.info("Install with: pip install rarfile")

    logger.info("Starting AI-Powered Security Analysis Web App")
    logger.info(f"Upload folder: {app.config['UPLOAD_FOLDER']}")
    logger.info(f"Results folder: {app.config['RESULTS_FOLDER']}")

    app.run(debug=True, host='0.0.0.0', port=5000)
