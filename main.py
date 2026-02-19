#!/usr/bin/env python3
"""
Enterprise Wazuh Critical Attacker Analysis System - Advanced GUI with Real Data
Integrated version combining CLI analyzer with GUI interface

Author: Security Operations Team
Version: 6.0.0 Professional
License

: MIT
"""

# Suppress TensorFlow verbose messages BEFORE importing any modules
import os
import warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # 0=all, 1=info, 2=warning, 3=error
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'  # Disable oneDNN messages
warnings.filterwarnings('ignore', category=UserWarning, module='google.protobuf')

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, font
import customtkinter as ctk
from PIL import Image, ImageTk, ImageDraw
import asyncio
import aiohttp
import threading
import requests
import json
import urllib3
import logging
import re
import ipaddress
import hashlib

import pickle
import sys
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple, Optional, Any, Union
from collections import defaultdict, Counter, deque
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from functools import lru_cache, wraps
from pathlib import Path
import pandas as pd
import numpy as np
from enum import Enum
import yaml
import queue
import time
import random
import configparser
import webbrowser
import socket
import struct

# Advanced plotting
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
from matplotlib.animation import FuncAnimation
import matplotlib.patches as mpatches
from matplotlib.patches import Circle, Rectangle, FancyBboxPatch
import matplotlib.patheffects as path_effects
import seaborn as sns

# For geographic visualization
try:
    import folium
    from folium import plugins
    FOLIUM_AVAILABLE = True
except ImportError:
    FOLIUM_AVAILABLE = False

# For network graph visualization
try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

# Plotly for advanced interactive charts
try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import plotly.offline as pyo
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import warnings
warnings.filterwarnings('ignore')

# Suppress CustomTkinter 'bad window path name' errors on Windows
# This is a known issue where CTkToplevel's titlebar color callback fires after window destruction
class TkErrorHandler:
    """Custom Tk error handler to suppress non-fatal CustomTkinter errors"""
    def __call__(self, exc, val, tb):
        import traceback
        error_str = str(val)
        # Suppress known non-fatal CTkToplevel errors on Windows
        if "bad window path name" in error_str:
            return  # Silently ignore this non-fatal error
        # Print other exceptions normally
        traceback.print_exception(exc, val, tb)

# Install the custom error handler for Tk callbacks
tk.Tk.report_callback_exception = TkErrorHandler()

# Core modules
from modules.AdvancedWazuhGUI import AdvancedWazuhGUI
from modules.AgentProfile import AgentProfile
from modules.AttackDetector import AttackDetector
from modules.AttackerProfile import AttackerProfile
from modules.AttackEvent import AttackEvent
from modules.AttackPattern import AttackPattern
from modules.AttackType import AttackType
from modules.CacheManager import CacheManager
from modules.CLIConfiguration import CLIConfiguration
from modules.ConfigManager import ConfigManager
from modules.CriticalAttackerAnalyzer import CriticalAttackerAnalyzer
from modules.DataSource import DataSource
from modules.ElasticsearchDataSource import ElasticsearchDataSource
from modules.GeoIPEnricher import GeoIPEnricher
from modules.IPExtractor import IPExtractor
from modules.Severity import Severity
from modules.SmartIPExtractor import SmartIPExtractor
from modules.ThreatIntelligenceEnricher import ThreatIntelligenceEnricher

# Enterprise Analytics & ML (Phase 1)
from modules.AuditLogger import AuditLogger
from modules.MLAnomalyDetector import MLAnomalyDetector
from modules.AdvancedMLEngine import AdvancedMLEngine
from modules.MLModelManager import MLModelManager
from modules.ThreatIntelHub import ThreatIntelHub
from modules.ComplianceManager import ComplianceManager
from modules.PerformanceOptimizer import PerformanceOptimizer

# Stream Processing & Analytics (Phase 2)
from modules.StreamProcessor import StreamProcessor, AttackStreamProcessor
from modules.CEPEngine import CEPEngine
from modules.TimeSeriesForecaster import TimeSeriesForecaster
from modules.TrendAnalyzer import TrendAnalyzer
from modules.CorrelationEngine import CorrelationEngine
from modules.AttackChainReconstructor import AttackChainReconstructor
from modules.InvestigationWorkflow import InvestigationWorkflowEngine
from modules.ImageOptimizer import ImageOptimizer

# Compliance & Privacy (Phase 3)
from modules.ThreatActorProfiler import ThreatActorProfiler
from modules.AutomatedEvidenceCollector import AutomatedEvidenceCollector
from modules.IoCMatcher import IoCMatcher
from modules.DataPrivacyManager import DataPrivacyManager
from modules.ComplianceReporter import ComplianceReporter
from modules.EnterpriseReportGenerator import EnterpriseReportGenerator

# Threat Intelligence & MITRE ATT&CK
from modules.MitreAttackMapper import MitreAttackMapper, MitreTactic, MitreTechnique
from modules.ThreatIntelligenceAggregator import ThreatIntelligenceAggregator

# Set appearance - read from config, fallback to dark
_config_manager = ConfigManager()
_saved_theme = _config_manager.get('UI', 'theme', 'dark')
ctk.set_appearance_mode(_saved_theme if _saved_theme in ['dark', 'light'] else 'dark')
ctk.set_default_color_theme("blue")

# Color schemes for the GUI - Dark and Light themes
DARK_COLORS = {
    'bg_primary': '#0f1419',
    'bg_secondary': '#1a1f2e',
    'bg_tertiary': '#252d3f',
    'accent': '#00d4ff',
    'danger': '#ff4444',
    'warning': '#ffaa44',
    'success': '#44ff44',
    'text_primary': '#ffffff',
    'text_secondary': '#a0a0a0',
    'chart_colors': ['#00d4ff', '#ff4444', '#44ff44', '#ffaa44', '#ff44ff', '#44ffff']
}

LIGHT_COLORS = {
    'bg_primary': '#f0f0f0',
    'bg_secondary': '#ffffff',
    'bg_tertiary': '#e0e0e0',
    'accent': '#0078d4',
    'danger': '#d13438',
    'warning': '#ffb900',
    'success': '#107c10',
    'text_primary': '#000000',
    'text_secondary': '#505050',
    'chart_colors': ['#0078d4', '#d13438', '#107c10', '#ffb900', '#8764b8', '#00b7c3']
}

# CTk-compatible dual-mode colors (light_color, dark_color) - AUTO-SWITCHES with theme!
COLORS = {
    'bg_primary': ('#f0f0f0', '#0f1419'),
    'bg_secondary': ('#ffffff', '#1a1f2e'),
    'bg_tertiary': ('#e0e0e0', '#252d3f'),
    'accent': ('#0078d4', '#00d4ff'),
    'danger': ('#d13438', '#ff4444'),
    'warning': ('#ffb900', '#ffaa44'),
    'success': ('#107c10', '#44ff44'),
    'text_primary': ('#000000', '#ffffff'),
    'text_secondary': ('#505050', '#a0a0a0'),
    'chart_colors': ['#0078d4', '#d13438', '#107c10', '#ffb900', '#8764b8', '#00b7c3']
}

def get_theme_colors():
    """Get single-value colors based on current theme"""
    return LIGHT_COLORS if _saved_theme == 'light' else DARK_COLORS

def main():
    """Main application entry point"""
    # Configure matplotlib based on theme
    if _saved_theme == 'light':
        plt.style.use('default')
    else:
        plt.style.use('dark_background')
    
    # Create root window
    root = ctk.CTk()
    
    # Set window properties
    root.title("Wazuh Advanced Security Operations Center")
    root.geometry("1400x900")
    
    # Set icon (if available)
    try:
        root.iconbitmap("assets/wazuh_icon.ico")
    except (tk.TclError, FileNotFoundError):
        pass
        
    # Create application
    app = AdvancedWazuhGUI(root)
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Run application
    root.mainloop()


if __name__ == "__main__":
    main()