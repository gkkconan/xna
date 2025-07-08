# eNanalyser

**eNanalyser** is an advanced, plugin-based network analysis toolkit designed for real-time monitoring, anomaly detection using machine learning, vulnerability scanning via API, phishing emulation, and more.

It is fully open-source and supports both **Standard** and **Premium** feature sets through a single configuration variable.

> [!WARNING]  
> Use responsibly and only on networks you own or have permission to analyze. Misuse of this tool may violate laws or terms of service.

---

## Table of Contents
- [Overview](#enanalyser)
- [Features](#features)
- [Project Structure](#-project-structure)
- [Setup Instructions](#️-setup-instructions)
- [Dashboard](#dashboard)
- [Dependencies](#-dependencies)
- [License](#-license)
- [Authors](#-authors)
- [FAQ](#-faq)
- [Contributing](#-contributing)

---

### Features
- 🖥️ ARP scanning and network device detection using `scapy`
- 📊 Real-time interactive dashboard with `Dash` and `Plotly`
- 🧠 Network anomaly detection with `Isolation Forest`
- 🧪 Phishing site detection with optional HTTPS emulation
- 🔍 Exploit scanning via the `Vulners` API
- 🔌 Modular plugin system – extend or disable features easily
- 🔐 Toggle between Standard and Premium mode


### 📁 Project Structure
```plaintext
.
├── eNanalyser.py             # Main application (entry point)
├── train_model.py            # Trains ML model for anomaly detection
├── createSSLcertificate.py   # Creates HTTPS cert for phishing server
├── plugins/                  # All plugins (you can add your plugins to help the community)
├── api/                      # Vulners requirements api
├── assets/                   # styles
├── plugin_loader.py          # Is essentials to implement others plugins (do not modify this file!)
├── requirements.txt          # List of Python dependencies
├── LICENSE                   # Project license (GPLv3)
└── README.md                 # Quick documentation
```

### 🛠️ Setup Instructions
1. Install dependencies with `pip install -r requirements.txt` (Ensure you are using Python 3.7)
2. Train the ADM (Anomaly Detection Model) with `python train_model.py`
   This will generate `isolation_forest_model.joblib`, which is required by `eNanalyser.py`.
3. (Optional) Enable HTTPS for Phishing Detection (self-signed SSL certificate)
   Modify the certificate details in `createSSLcertificate.py` and then run `python createSSLcertificate.py`
4. Add Vulners API Key
   - Get your key from [Vulners](https://vulners.com) -> My API
   - Set `VULNERS_API_KEY = \"YOURAPIKEY\"` in `plugins/exploit_finder.py`
5. Set access mode (Standard or Premium) to enable premium-only features
   - Set the `IS_PREMIUM_USER = False` variable in `eNanalyser.py`
6. Launch the application
   - Once everything is set up, run the app with `python eNanalyser.py`
   - Follow the prompts to enter any required configuration data
   - A link to the real-time dashboard will appear in the terminal


### Dashboard
The dashboard has the following options:
- Network topology
- Detected devices
- Anomaly alerts
- Plugin-specific outputs (e.g., exploits, phishing attempts)


### 📦 Dependencies
Here there's a list with major dependencies used:
- scapy
- nmap
- pyshark
- dash
- plotly
- flask, flask_talisman
- mac_vendor_lookup
- psutil
- socket
- requests
- subprocess
- sklearn
- joblib
- numpy
- networkx
- threading
- datetime
> See requirements.txt for the full list.


## 🔐 License
This project is licensed under the [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).  
> See the [LICENSE](LICENSE) file for details.


### 👤 Authors
- [Manuel Sarullo](https://github.com/M4nuel0) - Creator and Maintainer


### 🙋 FAQ
1. Q: Is this tool safe to run on my own network?  
   A: Yes, all scanning and analysis is done locally. However, always use it responsibly and legally.
2. Q: Can I add my own plugins?  
   A: Absolutely! Just drop a new Python file into the plugins/ directory and follow the structure of the existing plugins.
3. Q: Can I disable premium-only plugins?  
   A: Yes — simply set IS_PREMIUM_USER = False in eNanalyser.py.


### 🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.  
If you enjoy this project, feel free to give it a ⭐.
