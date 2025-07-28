import dash
from dash import html, Output, Input
import subprocess
import sys
import threading
import webbrowser

# Initialize the Dash app
app = dash.Dash(__name__)

# Override the Dash HTML template to include the particles.js background div and script
app.index_string = '''
<!DOCTYPE html>
<html>
  <head>
    {%metas%}
    <title>{%title%}</title>
    {%favicon%}
    {%css%}
    <script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
  </head>
  <body>
    <div id="particles-js" 
         style="position: fixed; width: 100%; height: 100%; z-index: -1; top: 0; left: 0;">
    </div>
    {%app_entry%}
    <footer>
        {%config%}
        {%scripts%}
        {%renderer%}
    </footer>
    <script>
      /* Configure particles */
      particlesJS('particles-js', {
        "particles": {
          "number": { "value": 80 },
          "color": { "value": "#00ffcc" },
          "shape": { "type": "circle" },
          "opacity": { "value": 0.5 },
          "size": { "value": 3 },
          "line_linked": { "enable": true, "distance": 150, "color": "#00ffcc", "opacity": 0.4, "width": 1 },
          "move": { "enable": true, "speed": 2 }
        },
        "interactivity": {
          "events": { "onhover": { "enable": true, "mode": "repulse" } }
        },
        "retina_detect": true
      });
    </script>
  </body>
</html>
'''

# Layout with foreground colors matched to the particle background
app.layout = html.Div(
    style={
        'position': 'relative',
        'zIndex': 10,  # make sure UI is above particles background
        'textAlign': 'center',
        'padding': '40px',
        'fontFamily': 'Arial, sans-serif',
        'minHeight': '100vh',
        'color': '#00ffcc',  # base text color (cyan)
    },
    children=[
        html.H2(
            "Project Launcher",
            style={
                'color': '#00ffcc',
                'marginBottom': '40px',
                'textShadow': '0 0 8px #00ffcc'  # subtle glow
            }
        ),
        html.Button(
            "Run Web SQLi Scanner",
            id="btn-sqli",
            n_clicks=0,
            style={
                'width': '250px',
                'height': '45px',
                'margin': '20px',
                'backgroundColor': '#1abc9c',  # turquoise teal
                'color': '#e0ffff',            # very light cyan text
                'borderRadius': '8px',
                'fontWeight': 'bold',
                'border': 'none',
                'cursor': 'pointer',
                'boxShadow': '0 0 10px #1abc9c',  # glow effect
            }
        ),
        html.Button(
            "Run DDoS Detection System",
            id="btn-ddos",
            n_clicks=0,
            style={
                'width': '250px',
                'height': '45px',
                'margin': '20px',
                'backgroundColor': '#9b59b6',  # deep purple
                'color': '#e0ffff',             # very light cyan text
                'borderRadius': '8px',
                'fontWeight': 'bold',
                'border': 'none',
                'cursor': 'pointer',
                'boxShadow': '0 0 10px #9b59b6',  # glow effect
            }
        ),
        html.Div(
            id='status',
            style={
                'marginTop': '40px',
                'fontSize': '1.1em',
                'color': '#27ae60'  # green status messages
            }
        ),
        html.Div(
            "Tip: Check console for live logs!",
            style={
                'marginTop': '20px',
                'fontSize': '0.95em',
                'color': '#7f8c8d'  # subdued grey tip
            }
        ),
    ]
)

def run_script(script_name, port):
    """Runs the given Python script in a separate thread and opens the browser."""
    def target():
        subprocess.Popen([sys.executable, script_name])
    threading.Thread(target=target, daemon=True).start()
    threading.Timer(3.0, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()

@app.callback(
    Output('status', 'children'),
    Input('btn-sqli', 'n_clicks'),
    Input('btn-ddos', 'n_clicks'),
    prevent_initial_call=True
)
def launch_tools(n_clicks_sqli, n_clicks_ddos):
    ctx = dash.callback_context
    if not ctx.triggered:
        return dash.no_update

    btn_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if btn_id == 'btn-sqli':
        run_script('scripts/web_ch1.py', 5001)
        return "Launching Web SQLi Scanner..."

    elif btn_id == 'btn-ddos':
        run_script('scripts/try2.py', 5002)
        return "Launching DDoS Detection System..."

    return dash.no_update

if __name__ == "__main__":
    app.run_server(debug=True, port=8080)
