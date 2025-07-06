import json
from datetime import datetime
import os
from dash import html

# Generate a snapshot from a Dash figure
def generate_snapshot(figure):
    try:
        if len(figure['data']) < 2 or 'customdata' not in figure['data'][1]:
            print("[!] Figure data insufficient for snapshot")
            return None
        customdata = figure['data'][1]['customdata']
        snapshot = {
            'nodes': customdata,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        return snapshot
    except Exception as e:
        print(f"[!] Error generating snapshot: {e}")
        return None
    

#Generate a snapshot everytime that the user restart the software
def generate_and_save_snapshot(figure, filename="snapshot_auto.json"):
    snapshot = None
    try:
        snapshot = snapshot_dec("generate", figure=figure)
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

    if not snapshot:
        print("[!] Snapshot generation failed or returned None")
        return None

    # Save in Indented JSON
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=4)
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

    #Return snapshot
    return snapshot


#Compare auto snapshot and old snapshot of the network
def compare_snapshots_data(old_snapshot, current_snapshot):
    if not old_snapshot or not current_snapshot:
        return html.Div("❌ One or both snapshots are missing or invalid.", style={'color': 'red'})

    try:
        old_nodes = {line.split('\n')[0].split(": ")[1] for line in old_snapshot['nodes']}
        new_nodes = {line.split('\n')[0].split(": ")[1] for line in current_snapshot['nodes']}
    except (KeyError, IndexError):
        return html.Div("⚠️ Snapshot data format error.", style={'color': 'orange'})

    added = new_nodes - old_nodes
    removed = old_nodes - new_nodes

    children = []

    if added:
        children.append(html.Div("🟢 New devices:", style={'fontWeight': 'bold', 'marginTop': '1rem', 'textAlign': 'center'}))
        children.append(html.Ul(
            [html.Li(dev, style={'padding': '4px 0', 'textAlign': 'center'}) for dev in sorted(added)],
            style={'listStyleType': 'none', 'padding': 0, 'margin': 0}
        ))
    if removed:
        children.append(html.Div("🔴 Removed devices:", style={'fontWeight': 'bold', 'marginTop': '1rem', 'textAlign': 'center'}))
        children.append(html.Ul(
            [html.Li(dev, style={'padding': '4px 0', 'textAlign': 'center'}) for dev in sorted(removed)],
            style={'listStyleType': 'none', 'padding': 0, 'margin': 0}
        ))
    if not children:
        children.append(html.Div("✅ No changes in device list.", style={'color': 'green', 'marginTop': '1rem', 'textAlign': 'center'}))

    return html.Div(children)



# Load the saved snapshot from disk
def load_saved_snapshot():
    try:
        with open("saved_snapshot.json") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# Save the current snapshot to disk
def save_snapshot(snapshot):
    try:
        with open("saved_snapshot.json", "w") as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Failed to save snapshot: {e}")

# Plugin entrypoint
def snapshot_dec(action, **kwargs):
    if action == "generate":
        return generate_snapshot(kwargs.get("figure"))
    elif action == "compare":
        return compare_snapshots_data(kwargs.get("old_snapshot"), kwargs.get("current_snapshot"))
    elif action == "load":
        return load_saved_snapshot()
    elif action == "save":
        save_snapshot(kwargs.get("snapshot"))
        return True
    else:
        return None
