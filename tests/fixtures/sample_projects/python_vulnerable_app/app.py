# Sample vulnerable Python app
# CVE-2019-1010317: Flask before 1.1.0 has vulnerable debug mode

from flask import Flask, request, render_template_string

app = Flask(__name__)
app.debug = True  # VULNERABLE: Debug mode enabled in production-like setting

# VULNERABLE: render_template_string with user input
@app.route('/render', methods=['POST'])
def render_template():
    template = request.form.get('template', '')

    try:
        # This is vulnerable - user input goes directly to template engine
        result = render_template_string(template)
        return result
    except Exception as e:
        return str(e)

# SAFE: Only serving static content
@app.route('/api/data')
def get_data():
    return {'data': 'Hello World'}

if __name__ == '__main__':
    app.run()
