from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return jsonify({"status": "healthy", "message": "Global Clinic API running on Railway"})

@app.route('/api/status')
def status():
    return jsonify({"status": "healthy", "message": "API working"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
