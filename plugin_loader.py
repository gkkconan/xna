# eNanalyser - Network analysis tool
# Copyright (c) 2025 Manuel Sarullo
# Licensed under the GNU General Public License v3.0 (GPL-3.0)


import importlib.util
import os

PLUGIN_FOLDER = "plugins"
PLUGIN_FUNCTIONS = {}

def load_plugins():
    global PLUGIN_FUNCTIONS
    for filename in os.listdir(PLUGIN_FOLDER):
        if filename.endswith(".py") and not filename.startswith("__"):
            plugin_path = os.path.join(PLUGIN_FOLDER, filename)
            module_name = filename[:-3]  # remove ".py"

            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Trova tutte le funzioni definite nel modulo
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if callable(attr):
                    PLUGIN_FUNCTIONS[attr_name] = attr

def get_plugin(name):
    return PLUGIN_FUNCTIONS.get(name)
