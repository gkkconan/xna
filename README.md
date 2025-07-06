# eNanalyser

**eNanalyser** is an advanced, plugin-based network analysis toolkit designed for real-time monitoring, anomaly detection using machine learning, vulnerability scanning via API, phishing emulation, and much more.

It is fully open-source and supports both **Standard** and **Premium** feature sets via a single configuration variable.

---

## 🚀 Features

- 🖥️ ARP scanning and network device detection using `scapy`
- 📊 Real-time interactive dashboard with `Dash` and `Plotly`
- 🧠 Network anomaly detection with `Isolation Forest`
- 🧪 Phishing site detection with optional HTTPS emulation
- 🔍 Exploit scanning via the `Vulners` API
- 🔌 Modular plugin system – extend or disable features easily
- 🔐 Toggle between Standard and Premium mode

---

## 📁 Project Structure

.
├── eNanalyser.py # Main application (entry point)
├── train_model.py # Trains ML model for anomaly detection
├── createSSLcertificate.py # Creates HTTPS cert for phishing server
├── plugins/
│ └── ALL plugins (You can add your plugins to help the community)
├── api/ #Vulners requirements api
├── assets/ # Static CSS and web files
├── plugin_loader.py #Is essentials to implement others plugins, you have not to modify this file!
├── requirements.txt # List of Python dependencies
├── LICENSE # Project license (GPLv3)
└── README.md # This file


---

## 🛠️ Setup Instructions

1. Install Dependencies

Ensure you are using **Python 3.7+**, then install the required packages:

pip install -r requirements.txt


2. Train the Anomaly Detection Model

Before using the dashboard, train the machine learning model:

python train_model.py

This will generate a file: isolation_forest_model.joblib, required by eNanalyser.py.


3. (Optional) Enable HTTPS for Phishing Detection

To generate a self-signed SSL certificate (for educational phishing emulation):

Open createSSLcertificate.py

Modify the certificate details inside the script (as described in the comments)

Then run:

python createSSLcertificate.py


4. Insert Vulners API Key (Required for Exploit Finder)

The plugin plugins/exploit_finder.py requires a Vulners API key.

How to get your Vulners API Key:

Go to https://vulners.com

Sign up or log in

Navigate to My API to get your personal key

Insert it in exploit_finder.py:

VULNERS_API_KEY = "YOURAPIKEY"


5. Set Access Mode (Standard or Premium)

Open eNanalyser.py and find this line:

IS_PREMIUM_USER = False

Set it to True if you want to enable premium-only plugins and features.


6. Launch the Application

Once everything is ready, run the application with:


python eNanalyser.py 

A Terminal will open in your desktop and you have to answer and insert your data, then wait until the software analyse your network
Then in the terminal will appear a link similar to "http//:127.0.0.1:8500", You have to copy this link in your browser 
And then web-based dashboard will open in your browser, showing:

Network topology

Detected devices

Anomaly alerts

Plugin-specific outputs (e.g., exploits, phishing attempts)



### 📦 Dependencies

1. Major libraries used:

scapy

nmap

pyshark

dash, plotly, flask, flask_talisman

mac_vendor_lookup

psutil, socket, requests, subprocess

sklearn, joblib, numpy

networkx, threading, datetime

See requirements.txt for the full list.



### 🔐 License

This project is licensed under the GNU General Public License v3.0 (GPLv3).

- You are free to:

1. Use it privately or commercially

2. Modify it

3. Share it

- As long as:

You keep it open-source

1. You include this same license

2. You give proper credit to the original author

See the LICENSE file for the full text of the license.



### 👤 Author

Created by: Manuel Sarullo
GitHub: https://github.com/M4nuel0

If you enjoy this project, feel free to give it a ⭐ on GitHub!



### 🙋 FAQ

1. Q: Is this tool safe to run on my own network?
   A: Yes, all scanning and analysis is done locally. However, always use it responsibly and legally.

2. Q: Can I add my own plugins?
   A: Absolutely! Just drop a new Python file into the plugins/ directory and follow the structure of the existing plugins.

3. Q: Can I disable premium-only plugins?
   A: Yes — simply set IS_PREMIUM_USER = False in eNanalyser.py.



### ⭐ Support This Project

If you found this project useful:

🌟 Star this repository


### 🍴 Fork it

🧵 Share it with others



Thanks for helping spread the word!