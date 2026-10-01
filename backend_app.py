from flask import Flask, request, render_template_string

app = Flask(__name__)

# Standard HTML Template for the target web application
BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Academic Search Portal</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 50px; background-color: #f4f6f9; color: #333; }
        .container { max-width: 600px; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin: auto; }
        h2 { color: #1e3d59; }
        input[type="text"] { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        input[type="submit"] { background-color: #1e3d59; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; font-size: 16px; }
        input[type="submit"]:hover { background-color: #17b978; }
        .results { margin-top: 20px; padding: 15px; background: #e8eef1; border-left: 5px solid #1e3d59; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Department Search Database</h2>
        <form action="/search" method="GET">
            <label for="q">Enter Search Keyword:</label>
            <input type="text" id="q" name="q" placeholder="Type query here..." required>
            <input type="submit" value="Execute Query">
        </form>
        {% if query %}
        <div class="results">
            <h3>Query Processing Result:</h3>
            <p>Search execution completed successfully for parameter: <strong>{{ query }}</strong></p>
            <p>Status: <span style="color: green; font-weight: bold;">200 OK (Clean Request Passed)</span></p>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/')
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template_string(BASE_TEMPLATE, query=query)

if __name__ == '__main__':
    # Binds directly to the private port inside the Docker network structure
    app.run(host='0.0.0.0', port=5001)