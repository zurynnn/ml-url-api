from flask import Flask, request, jsonify
from predict import predict_url
import os

app = Flask(__name__)

# Home route (testing)
@app.route("/")
def home():
    return "ML URL Detection API is running 🚀"

# Predict route
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url") # Get URL from request

    if not isinstance(url, str) or not url.strip():
        return jsonify({"result": "Invalid URL", "final_url": ""}), 400

    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    prediction = predict_url(url)

    return jsonify({
        "url": url,
        "result": prediction["result"],        # ← read from dict
        "final_url": prediction["final_url"],  # ← pass final_url to Flutter
    })

# Run server
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)