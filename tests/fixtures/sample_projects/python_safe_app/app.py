# Sample safe Python app - dependencies have vulns but not exploited

from flask import Flask, request, render_template, jsonify

app = Flask(__name__)
app.debug = False  # SAFE: Debug mode disabled

# SAFE: Using render_template with static template files only
@app.route('/page/<page_name>')
def render_page(page_name):
    # Static template name from URL parameter is safe
    return render_template(f'{page_name}.html')

# SAFE: Only serving JSON data
@app.route('/api/users')
def get_users():
    users = [
        {'id': 1, 'name': 'Alice'},
        {'id': 2, 'name': 'Bob'},
    ]
    return jsonify(users)

# SAFE: POST endpoint with safe handling
@app.route('/api/user', methods=['POST'])
def create_user():
    data = request.get_json()
    # No vulnerable functions called
    return jsonify({'created': True, 'name': data.get('name')})

if __name__ == '__main__':
    app.run(debug=False)
