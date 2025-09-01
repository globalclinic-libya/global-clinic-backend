from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/status')
def status():
    return {"status": "healthy", "message": "Global Clinic API is running"}

def handler(request):
    return app(request.environ, lambda status, headers: None)
