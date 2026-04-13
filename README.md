## Secure Chat Client Application

This is a Python application that sends encrypted messages to the Secure Chat server.

Install dependencies:
```shell
python3 -m venv ven
source venv/bin/activate
pip install -r requirements.txt
```

Run application:
This runs a command-line interactive UI, exposing core functionality of the messaging app.
Re-run the application for additional commands.
```shell
python3 client.py
```

By default, this connects to the http://localhost:25780/, but this can be changed by setting the
SERVER_URL environment variable:
```shell
SERVER_URL="https://localhost:8000/ python3 client.py  
```