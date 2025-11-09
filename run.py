from capture.sniffer import start_sniffing
from dashboard.app import app

if __name__ == "__main__":
    start_sniffing()
    app.run(debug=True)
