@app.route("/")
def home():
    return send_from_directory(".", "index.html")
