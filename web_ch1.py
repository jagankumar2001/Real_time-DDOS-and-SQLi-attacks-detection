from flask import Flask, render_template, request
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import os

app = Flask(__name__, template_folder='template')

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql_fetch",
    "ORA-00933", "ORA-00936", "ORA-01756",
    "sql syntax error",
    "Microsoft JET Database",
    "ODBC SQL Server Driver"
]

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL,table_name FROM information_schema.tables--",
    "' OR SLEEP(5)--"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SQLiScanner/1.0)"
}


class SecureSQLiScanner:
    def __init__(self, url):
        self.url = url if url.startswith("http") else "http://" + url
        self.vulnerable = False
        self.details = []

    def find_forms(self):
        try:
            res = requests.get(self.url, headers=HEADERS, timeout=10)
            soup = BeautifulSoup(res.content, "html.parser")
            return soup.find_all("form")
        except Exception:
            return []

    def get_form_details(self, form):
        details = {}
        try:
            action = form.attrs.get("action", "").strip()
            method = form.attrs.get("method", "get").lower()
            inputs = []
            for tag in form.find_all("input"):
                name = tag.attrs.get("name")
                type_ = tag.attrs.get("type", "text")
                if name:
                    inputs.append({"name": name, "type": type_})
            details["action"] = urljoin(self.url, action)
            details["method"] = method
            details["inputs"] = inputs
        except Exception:
            pass
        return details

    def scan_form(self, form_details, payload):
        data = {}
        for input_tag in form_details["inputs"]:
            if input_tag["type"] == "text":
                data[input_tag["name"]] = payload
            else:
                data[input_tag["name"]] = "test"
        try:
            if form_details["method"] == "post":
                res = requests.post(form_details["action"], data=data, headers=HEADERS, timeout=10)
            else:
                res = requests.get(form_details["action"], params=data, headers=HEADERS, timeout=10)
            for error in SQL_ERRORS:
                if error.lower() in res.text.lower():
                    return True
        except Exception:
            return False
        return False

    def run_scan(self):
        forms = self.find_forms()
        for form in forms:
            form_details = self.get_form_details(form)
            for payload in SQL_PAYLOADS:
                if self.scan_form(form_details, payload):
                    self.vulnerable = True
                    self.details.append({
                        "form_action": form_details["action"],
                        "method": form_details["method"],
                        "payload": payload
                    })
        return {"vulnerable": self.vulnerable, "details": self.details}


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        if not url:
            return render_template("error.html", message="URL is required.")

        scanner = SecureSQLiScanner(url)
        result = scanner.run_scan()

        if result["vulnerable"]:
            return render_template("results.html", url=url, details=result["details"])
        else:
            return render_template("results.html", url=url, details=[], note="No vulnerabilities found.")

    return render_template("index.html")


if __name__ == "__main__":
    required_templates = ["index.html", "results.html", "error.html"]
    for tpl in required_templates:
        full_path = os.path.join(os.path.dirname(__file__), app.template_folder, tpl)
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Missing template: {tpl}")

    app.run(debug=True,port=5001)