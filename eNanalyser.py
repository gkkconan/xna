# eNanalyser - Network analysis tool
# Copyright (c) 2025 Manuel Sarullo
# Licensed under the GNU General Public License v3.0 (GPL-3.0)



from scapy.all import ARP, Ether, srp
import nmap
import time
from mac_vendor_lookup import MacLookup
import networkx as nx
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objects as go
import pyshark
from threading import Thread
from collections import defaultdict
from datetime import datetime
import psutil
import os
import asyncio
from sklearn.ensemble import IsolationForest
import numpy as np
from joblib import load
from dash.dependencies import ALL, MATCH
from dash.dependencies import Input, Output, State, ALL, MATCH
import requests
import json
import re
import socket
import requests
import subprocess
import threading
from flask import Flask, request, send_from_directory, render_template
from flask_talisman import Talisman
from html import escape as html_escape  #Has not conflicts with Dash




# === GLOBAL PREMIUM VARIABLE ===

IS_PREMIUM_USER = False

#Check plugin
if IS_PREMIUM_USER:
    from plugin_loader import load_plugins, get_plugin

# ===============================

# === SECURITY ===

def safe_text(text):
    return html_escape(str(text))

# ================

#IF YOU WANT VARIABLES LIKE ip COULD BE DINAMYC

# Define your target network subnet 
ip = str(input("\nTARGET IP: "))
target_ip = ip

# Global dictionary to store traffic statistics
traffic_stats = defaultdict(lambda: {"count": 0, "last_seen": None})

# Add tshark to PATH for pyshark to work properly (Windows-specific)
os.environ["PATH"] += os.pathsep + r"C:\Program Files\Wireshark" #Windows


# Get the name of an active network interface
def get_active_interface():
    interfaces = psutil.net_if_stats()
    for interface, stats in interfaces.items():
        if stats.isup and not interface.lower().startswith("loopback"):
            return interface
    return None

def train_if_needed():
    if not os.path.exists("isoforest_model.pkl"):
        print("[*] Model not found. Start Training...")
        from train_model import main as train_main
        train_main()
        print("[*] Training completed.")

ml_model = load("isoforest_model.pkl")
trained = True

# Feature extraction function used for anomaly detection
# Extract 3 key features from packets of a given IP:
# - total packet count
# - number of unique protocols used
# - average packet length
def extract_features(ip):
    packets = live_packets[ip]
    if not packets:
        return None

    count_packets = len(packets)
    protocols = set(p['protocol'] for p in packets)
    count_protocols = len(protocols)
    avg_len = np.mean([len(p['info']) for p in packets])

    return np.array([count_packets, count_protocols, avg_len]).reshape(1, -1)



# Centralized anomaly detection function 
def detect_anomaly(ip):
    global trained, ml_model

    features = extract_features(ip)
    if features is None:
        return "unknown"

    pred = ml_model.predict(features)[0]

    return "anomalous" if pred == -1 else "normal"
    
    
#Get my IP
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        #Default address ip
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip





# Set the network interface to sniff on
interface = str(input("\nSET YOUR INTERFACE (ex. Wi-Fi): "))
iface = interface

# Global packet buffer
live_packets = defaultdict(list)

# Background packet sniffer
def start_sniffer(interface=iface):
    try:
        print(f"\n[+] Starting pyshark sniffer on interface: {interface}")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def process_packet(pkt):
            try:
                if not hasattr(pkt, 'ip'):
                    return  # Ignore non-IP packets

                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                protocol = pkt.highest_layer
                time_seen = datetime.now().strftime("%H:%M:%S")
                length = int(pkt.length)

                packet_info = {
                    "timestamp": time_seen,
                    "src": src_ip,
                    "dst": dst_ip,
                    "protocol": protocol,
                    "info": str(pkt),
                    "anomaly": False
                }

                traffic_stats[src_ip]["count"] += 1
                traffic_stats[src_ip]["last_seen"] = time_seen
                live_packets[src_ip].append(packet_info)

                if len(live_packets[src_ip]) > 100:
                    live_packets[src_ip] = live_packets[src_ip][-100:]

                # Use centralized anomaly detection logic
                if trained:
                    status = detect_anomaly(src_ip)
                    packet_info["anomaly"] = (status == "anomalous")

            except Exception as e:
                print(f"[!] Error processing packet: {e}")

        capture = pyshark.LiveCapture(interface=interface)
        capture.apply_on_packets(process_packet, packet_count=None)
    
    except Exception as e: 
        print(f"Error in the interface's setting: {e}")

#START SNIFFING
def launch_sniffer_thread():
    sniffer_thread = Thread(target=start_sniffer, kwargs={'interface': iface}, daemon=True)
    sniffer_thread.start()

#SCAN PORTS FUNCTION
def scan_ports(ip):
    scanner = nmap.PortScanner()
    #UPDATE NUMBER OF PORTS if you want
    scanner.scan(ip, arguments='-p 1-1000 -sV  ')
    services = []

    if ip in scanner.all_hosts():
        for proto in scanner[ip].all_protocols():
            for port in scanner[ip][proto]:
                name = scanner[ip][proto][port].get('name', 'unknown')
                services.append(f"{port}/{proto.upper()} ({name})")
    return services

#OS DETECTION FUNCTION
def oSDetection(ip):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip, arguments='-O')
    if ip in scanner.all_hosts() and 'osmatch' in scanner[ip]:
        os_matches = scanner[ip]['osmatch']
        if os_matches:
            return f"{os_matches[0]['name']} ({os_matches[0]['accuracy']}%)"
    return "Unknown OS"

#ASSESS RISK FUNCTION
def assess_risk(device):
    risk_score = 0
    if "Unknown" in device["os"] or "Windows XP" in device["os"] or "lwIP" in device["os"]:
        risk_score += 2
    dangerous_services = ["telnet", "ftp", "ssh", "rdp"]
    if any(service for service in device["services"] if any(d in service for d in dangerous_services)):
        risk_score += 2
    if device["vendor"] == "Unknown Vendor":
        risk_score += 1
    if risk_score >= 4:
        return "high"
    elif risk_score >= 2:
        return "medium"
    else:
        return "low"

#Get color for protocol 
def get_color_for_protocol(proto):
    proto = proto.upper()
    if proto == "TCP":
        return "#ffcc00"
    elif proto == "UDP":
        return "#00bfff"
    elif proto == "ICMP":
        return "#ff3366"
    elif proto == "ARP":
        return "#aaaaaa"
    else:
        return "#00ff99"
    
#Function to the packet formatting 
def format_packet_details(packet):
    return [
        html.H4("Packet Details"),
        html.P(f"Timestamp: {packet['timestamp']}"),
        html.P(f"Source: {packet['src']}"),
        html.P(f"Destination: {packet['dst']}"),
        html.P(f"Protocol: {packet['protocol']}"),
        html.P("Full Info:"),
        html.Pre(packet['info'][:3000], style={'whiteSpace': 'pre-wrap', 'fontSize': '0.85rem'})
    ]
    

 
#DASHBOARD 

def run_dashboard(devices):
    G = nx.Graph()

    for device in devices:
        label = f"{device['ip']}\n{device['vendor']}\n{device['os']}"
        device['label'] = label
        G.add_node(device['ip'], **device)  # IP KEY

    for i in range(len(devices)):
        for j in range(i + 1, len(devices)):
            dev_a = devices[i]
            dev_b = devices[j]
            shared = set(dev_a['services']) & set(dev_b['services'])
            if shared:
                G.add_edge(dev_a['ip'], dev_b['ip'], services=', '.join(shared))

    pos = nx.spring_layout(G, k=3, seed=42)

    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1, color='#888'), hoverinfo='none', mode='lines')

    node_x, node_y, node_text = [], [], []
    for ip, data in G.nodes(data=True):
        x, y = pos[ip]
        node_x.append(x)
        node_y.append(y)
        text = (
            f"IP: {data['ip']}\n"
            f"MAC: {data['mac']}\n"
            f"Vendor: {data['vendor']}\n"
            f"OS: {data['os']}\n"
            f"User: {data.get('user', 'Unknown')}\n"
            f"Services: {' - '.join(data['services']) if data['services'] else 'None'}"
        )
        node_text.append(text)

    colors = {"low": "#00ff99", "medium": "#ffcc00", "high": "#ff3366"}
    node_colors = [colors[data.get("risk", "low")] for _, data in G.nodes(data=True)]

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode='markers+text', textposition="top center",
        hoverinfo='text', marker=dict(showscale=False, color=node_colors, size=30, line_width=2),
        text=[data['ip'] for _, data in G.nodes(data=True)],
        customdata=node_text
    )

    fig = go.Figure(data=[edge_trace, node_trace], layout=go.Layout(
        title=dict(text='Interactive Network Map', x=0.5, font=dict(size=20)),
        showlegend=False, hovermode='closest',
        margin=dict(b=20, l=5, r=5, t=40),
        xaxis=dict(showgrid=False, zeroline=False),
        yaxis=dict(showgrid=False, zeroline=False)
    ))

    app = dash.Dash(__name__, assets_folder='assets')
    
    #SECURITY HTTPS
    server = app.server  # Flask app

    # Talisman for security
    Talisman(
        server,
        content_security_policy={
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'"],
            'style-src': ["'self'", "'unsafe-inline'"],
        },
        force_https=False,  # IMPORTANT: set true in a deployment system
        strict_transport_security=True
    )
    app.title = "EN-ANALYSER"

    # Snapshot plugin check
    if IS_PREMIUM_USER:
        snapshot_plugin = get_plugin("snapshot_dec")
        if snapshot_plugin is None:
            print("[!] Plugin snapshot_dec not found")
            return  
        load_saved_snapshot = get_plugin("load_saved_snapshot")
        snapshot_data = load_saved_snapshot() if load_saved_snapshot else None
        
        from plugins.snapshot_tool import generate_and_save_snapshot

        snapshot_auto_data = generate_and_save_snapshot(fig)
        if snapshot_auto_data is None:
            snapshot_auto_data = {}  # fallback
    else:
        snapshot_data = {}

    #LAYOUT 
    app.layout = html.Div([
    dcc.Store(id='selected-ip', data=''),
    dcc.Store(id='packet-memory', data={}),
    dcc.Store(id='selected-packet', data={}),
    dcc.Store(id='panel-visible', data=False),
    dcc.Store(id='clicked-packet-index', data=None),
    dcc.Store(id='snapshot-storage', data=snapshot_data), #IF is not a PREMIUM USER set data={}
    dcc.Store(id='current-snapshot', data=snapshot_auto_data), #IF is not a PREMIUM USER set data={}
    dcc.Store(id='snapshot-comparison', data=''),

        

        html.Div([
            html.Div(id='packet-details', className='side-panel', children=[]),
            html.Div([
                html.H1("EN-ANALYSER"),
                html.H2("Cyber Intelligence Dashboard"),
                dcc.Graph(id='network-graph', figure=fig, config={'displayModeBar': False}),
                html.Div(id='node-info'),
                html.Div([
                    html.H3("Live Packet Feed"),
                    html.Pre(id='live-packets'),
                    
                    html.Div(
                        id="chatgpt-placeholder",
                        children=[
                            html.H3("CHAT-GPT ASSISTANT", style={"color": "#00ffe0"}),
                            html.Div(
                                "🚧 This feature will be available in a future release for Premium users",
                                style={
                                    "backgroundColor": "#111827",
                                    "color": "#e6e6e6",
                                    "border": "2px dashed #00ffe0",
                                    "padding": "20px",
                                    "marginTop": "20px",
                                    "borderRadius": "10px",
                                    "fontSize": "18px",
                                    "textAlign": "center",
                                },
                            ),
                        ],
                        style={"marginTop": "4rem", "textAlign": "center"}
                    ),
                ])
            ], className='main-content', id='main-content'),
            
            html.Div([
                html.H3("SNAPSHOT TOOL", id="snapshot-title"),
                html.Button("📸 Take Snapshot", id="btn-snapshot", n_clicks=0),
                html.Button("🔍 Compare Snapshot", id="btn-compare", n_clicks=0),
                html.Div(id="snapshot-result", style={'marginTop': '2rem', 'fontSize': '0.9rem'}),
                
                html.Div([
                    html.H3("SOCIAL ENGINEERING TOOL"),
                    html.Button("🎯 Launch Phishing Page", id="btn-phish", n_clicks=0),
                    html.Div(id="social-output", style={'marginTop': '1rem'}),
                    dcc.Interval(id='phish-check-interval', interval=5000, n_intervals=0)
                ], id="social-engineering-panel", style={'marginTop': '1.5rem'})
            ], className='side-panel snapshot-panel')
        ], className='flex-container', id="snapshot-tool"),
        

        dcc.Interval(id='interval-component', interval=1000, n_intervals=0)
    ])


    # Callback to show node's informations
    @app.callback(
    Output('node-info', 'children'),
    Output('selected-ip', 'data'),
    Input('network-graph', 'clickData')
    )
    def display_node_info(clickData):
        if clickData:
            raw_data = clickData['points'][0]['customdata']
            lines = raw_data.split('\n')
            ip = lines[0].split(": ")[1]

            node_data = G.nodes.get(ip, {})

            if IS_PREMIUM_USER:
                exploits = node_data.get('exploits', [])
                if isinstance(exploits, list) and exploits:
                    exploit_section = html.Div([
                        html.H4("\nKNOWN EXPLOITS:"),
                        html.Ul([
                            html.Li(html.A(exploit["title"], href=exploit["url"], target="_blank"))
                            for exploit in exploits
                        ])
                    ])
                else:
                    exploit_section = html.Div([
                        html.H4("\nKNOWN EXPLOITS:"),
                        html.P("No known exploits found.")
                    ])
            else:
                exploit_section = html.Div([
                    html.H4("\nKNOWN EXPLOITS:"),
                    html.P("🔒 This feature is only available to Premium users.")
                ])

            return html.Div([
                html.H4("DEVICE INFORMATION:\n"),
                html.Pre(raw_data),
                exploit_section
            ]), ip

        return "Click a node to see details.", ""




    #Callback to update the packets's feed
    @app.callback(
    Output('live-packets', 'children'),
    Output('packet-memory', 'data'),
    Input('interval-component', 'n_intervals'),
    Input('selected-ip', 'data'),
    State('packet-memory', 'data')
    )
    def update_packet_feed(n, selected_ip, memory):
        if not selected_ip:
            return "No live packets to display.", {}

        if memory is None:
            memory = {}

        if selected_ip not in memory:
            memory[selected_ip] = []

        packets = live_packets[selected_ip][-100:]

        existing_keys = {
            (safe_text(p['timestamp']), safe_text(p['src']), safe_text(p['dst']), safe_text(p['protocol'])) for p in memory[selected_ip]
        }

        new_packets = [
            p for p in packets
            if (safe_text(p['timestamp']), safe_text(p['src']), safe_text(p['dst']), safe_text(p['protocol'])) not in existing_keys
        ]

        memory[selected_ip].extend(new_packets)
        memory[selected_ip] = memory[selected_ip][-100:]

        packet_elements = []
        for index, p in enumerate(memory[selected_ip]):
            base_color = get_color_for_protocol(p['protocol'])
            is_anomalous = p.get("anomaly", False)
            color = "#ff4444" if is_anomalous else base_color

            display = f"[{safe_text(p['timestamp'])}] {safe_text(p['src'])} → {safe_text(p['dst'])} | {safe_text(p['protocol'])}"
            if is_anomalous:
                display += " ⚠️ ANOMALY -> YOU SHOULD ANALYSE"

            packet_elements.append(
                html.Div(display, style={'color': color, 'cursor': 'pointer'}, n_clicks=0, id={'type': 'packet-item', 'index': index})
            )

        return packet_elements, memory

    
    #Callback to show the packets's informations
    @app.callback(
    Output('packet-details', 'children'),
    Output('packet-details', 'style'),
    Output('selected-packet', 'data'),
    Output('panel-visible', 'data'),
    Input('clicked-packet-index', 'data'),
    State('selected-ip', 'data'),
    State('packet-memory', 'data'),
    prevent_initial_call=True
    )
    def show_packet_details(index, selected_ip, memory):
        if index is None or not selected_ip or not memory or selected_ip not in memory:
            return "", {'display': 'none'}, {}, False

        packet = memory[selected_ip][index]
        return format_packet_details(packet), {'display': 'block'}, packet, True



    #Function panel
    @app.callback(
    Output('packet-details', 'className', allow_duplicate=True),
    Input('panel-visible', 'data'),
    prevent_initial_call='initial_duplicate'
    )
    def toggle_panel_display(visible):
        return 'side-panel open' if visible else 'side-panel'



    #Intercept clicked packet
    @app.callback(
    Output('clicked-packet-index', 'data'),
    Input({'type': 'packet-item', 'index': ALL}, 'n_clicks'),
    prevent_initial_call=True
    )
    def store_clicked_packet_index(n_clicks_list):
        clicked_indices = [i for i, n in enumerate(n_clicks_list) if n]
        if not clicked_indices:
            return dash.no_update
        return clicked_indices[-1]
    
    
    #SNAPSHOT CALLBACK
    @app.callback(
    Output('snapshot-result', 'children'),
    Output('current-snapshot', 'data'),
    Input('btn-snapshot', 'n_clicks'),
    Input('btn-compare', 'n_clicks'),
    State('network-graph', 'figure'),
    State('current-snapshot', 'data'),
    State('snapshot-storage', 'data'),
    prevent_initial_call=True
    )
    def handle_snapshot_buttons(btn_snapshot_clicks, btn_compare_clicks, figure, current_snapshot, snapshot_memory):
        if not IS_PREMIUM_USER:
            return "🔒 This feature is only available to Premium users.", dash.no_update
        
        snapshot_plugin = get_plugin("snapshot_dec")

        ctx = dash.callback_context

        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if triggered_id == 'btn-snapshot':
            snapshot = snapshot_plugin("generate", figure=figure)
            if snapshot:
                return "\n📸 Snapshot taken at " + snapshot['timestamp'], snapshot
            else:
                return "\n⚠️ Failed to take snapshot.", dash.no_update
        elif triggered_id == 'btn-compare':
            if not snapshot_memory:
                return "\n❌ No previous snapshot to compare.", dash.no_update
            if not current_snapshot:
                return "\n❌ No current snapshot available. Take one first.", dash.no_update
            result = snapshot_plugin("compare", old_snapshot=snapshot_memory, current_snapshot=current_snapshot)
            return result, dash.no_update

        return dash.no_update, dash.no_update



    @app.callback(
    Output('snapshot-storage', 'data'),
    Input('current-snapshot', 'data'),
    prevent_initial_call=True
    )
    def save_snapshot_to_disk(current_snapshot):
        if not IS_PREMIUM_USER:
            return ""
        
        snapshot_plugin = get_plugin("snapshot_dec")

        if current_snapshot:
            snapshot_plugin("save", snapshot=current_snapshot)
            return current_snapshot
        return dash.no_update

    
    
    
    #SOCIAL ENGINEERING CALLBACK 
    @app.callback(
    Output('social-output', 'children'),
    Input('btn-phish', 'n_clicks'),
    prevent_initial_call=True
    )
    def launch_phishing_page(n):
        if not IS_PREMIUM_USER:
            return "🔒 This feature is only available to Premium users."
        
        phish_plugin = get_plugin("phish_dec")
        if phish_plugin:
            ip = get_local_ip()
            phish_plugin("start")
            return f'✅ Phishing page launched at http://{ip}:5001'
        return "❌ Failed to launch phishing page."

    
    #view attempts
    @app.callback(
    Output('social-output', 'children', allow_duplicate=True),
    Input('phish-check-interval', 'n_intervals'),
    prevent_initial_call=True
    )
    def update_phish_log(n):
        if not IS_PREMIUM_USER:
            return ""
        
        phish_plugin = get_plugin("phish_dec")
        if not phish_plugin:
            return dash.no_update

        logins = phish_plugin("get_log")
        if not logins:
            return dash.no_update

        log_list = html.Ul(
            [
                html.Li(
                    f"{safe_text(log['timestamp'])} | {safe_text(log['ip'])} | {safe_text(log['username'])} : {safe_text(log['password'])}",
                    style={'listStyleType': 'none', 'textAlign': 'center', 'marginTop': '1rem'}
                )
                for log in logins
            ],
            style={'padding': 0}
        )

        clear_button = html.Button("🧹 CLEAR LOG", id="clear-log-btn", n_clicks=0, style={'marginTop': '20px'})

        return html.Div([
            html.H4("CAPTURED CREDENTIALS:", style={'textAlign': 'center'}),
            log_list,
            clear_button
        ])

        
        
    #clear logs
    @app.callback(
    Output('social-output', 'children', allow_duplicate=True),
    Input('clear-log-btn', 'n_clicks'),
    prevent_initial_call=True
    )
    def clear_logs(n_clicks):
        if not IS_PREMIUM_USER:
            return ""
        
        if n_clicks > 0:
            phish_plugin = get_plugin("phish_dec")
            if phish_plugin:
                phish_plugin("clear")
                return html.Div("✅ Log clear", style={'textAlign': 'center'})
        return dash.no_update







    # === Run APP === 
    #If debug = True, there is an infinity reloaded loop in the cmd
    app.run(debug=False)
    



# === ANALYSE NETWORK ===   
#Analyse network using other functions
def netAnalyse():
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    mac = MacLookup()
    mac.update_vendors()
    
    if IS_PREMIUM_USER:
        #PLUGINS
        load_plugins()
        find_exploits = get_plugin("find_exploits_for_device")
        identify_user = get_plugin("user_identifier")
        snapshot_plugin = get_plugin("snapshot_tool")

    result = srp(packet, timeout=2, verbose=0)[0]

    print("\n\nDevices found on the network:")
    devices = []

    for sent, received in result:
        time.sleep(1)
        ip = received.psrc
        mac_addr = received.hwsrc

        try:
            vendor = mac.lookup(mac_addr)
        except Exception:
            vendor = "Unknown Vendor"

        try:
            print('\n' + '-' * 40)
            print(f"Host: {ip}\tMAC: {mac_addr}\tVendor: {vendor}")
            os_info = oSDetection(ip)
            services = scan_ports(ip)
            print(f"OS: {os_info}")
            print(f"Services: {', '.join(services) if services else 'None'}")

            risk_level = assess_risk({
                "ip": ip,
                "mac": mac_addr,
                "vendor": vendor,
                "os": os_info,
                "services": services
            })
            
            #Exploit plugin
            if IS_PREMIUM_USER:
                exploits = []
                if find_exploits:
                    exploits = find_exploits({
                        "ip": ip,
                        "mac": mac_addr,
                        "vendor": vendor,
                        "os": os_info,
                        "services": services
                    })
            else:
                exploits = "🔒 This feature is only available to Premium users."
            
            
            #User
            if IS_PREMIUM_USER:
                user = identify_user({
                    "ip": ip,
                    "mac": mac_addr,
                    "vendor": vendor,
                    "os": os_info,
                    "services": services
                })
            else:
                user = "🔒 This feature is only available to Premium users."

            device = {
                "ip": ip,
                "mac": mac_addr,
                "vendor": vendor,
                "os": os_info,
                "services": services,
                "risk": risk_level,
                "exploits": exploits,
                "user": user
            }

            devices.append(device)

        except Exception as e:
            print(f"Failed to analyze device {ip}: {e}")

    run_dashboard(devices)

#MAIN
def main():
    train_if_needed()
    launch_sniffer_thread()
    netAnalyse()

if __name__ == "__main__":
    main()
