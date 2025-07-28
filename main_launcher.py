import dash
from dash import html, dcc, Output, Input
import subprocess
import sys
import threading
import webbrowser

app = dash.Dash(__name__)

app.layout = html.Div(
    style={'textAlign': 'center', 'padding': '40px', 'fontFamily': 'Arial'},
    children=[
        html.H2("Project Launcher"),
        html.Button("Run Web SQLi Scanner", id="btn-sqli", n_clicks=0, style={'width': '250px', 'height': '45px', 'margin': '20px'}),
        html.Button("Run DDoS Detection System", id="btn-ddos", n_clicks=0, style={'width': '250px', 'height': '45px', 'margin': '20px'}),
        html.Div(id='status', style={'marginTop': '40px', 'fontSize': '1.1em', 'color': 'green'}),
        html.Div("Tip: Check console for live logs!", style={'marginTop': '20px', 'fontSize': '0.95em', 'color': '#555'}),
    ]
)

def run_flask_app(script_name, port):
    def target():
        subprocess.Popen([sys.executable, script_name])
    threading.Thread(target=target, daemon=True).start()
    threading.Timer(2.5, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()

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
        run_flask_app('web_ch1.py', 5001)
        return "Launching Web SQLi Scanner..."
    elif btn_id == 'btn-ddos':
        run_flask_app('try2.py', 5002)
        return "Launching DDoS Detection System..."

    return dash.no_update

if __name__ == "__main__":
    app.run_server(debug=True, port=8080)
