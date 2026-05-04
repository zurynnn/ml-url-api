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

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = predict_url(url) # Get prediction from ML model

    # Handle invalid URL case
    if result == "Invalid URL":
        return jsonify({
            "url": url,
            "result": "Invalid URL",
            "message": "The scanned QR does not contain a valid URL"
        }), 200

    return jsonify({
        "url": url,
        "result": result
    })

# Run server
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)