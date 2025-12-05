"""
Google Indexing API Tool
========================

A GUI application to interact with the Google Indexing API.
Allows users to publish (update) or remove URLs from the Google Index.

Author: ALI MARESH
License: MIT
"""

import os
import threading
import json
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, font
from google.oauth2 import service_account
from google.auth.transport.requests import AuthorizedSession

# --- Constants ---
SCOPES = ["https://www.googleapis.com/auth/indexing"]
INDEXING_ENDPOINT = "https://indexing.googleapis.com/v3/urlNotifications:publish"

# Theme Colors (Dark Modern)
COLOR_BG = "#0f1115"
COLOR_PANEL = "#14151A"
COLOR_ACCENT = "#6C63FF"
COLOR_TEXT = "#E6EDF3"
COLOR_MUTED = "#97A0B3"
COLOR_INPUT_BG = "#0d0f14"
COLOR_ERROR = "#FF6B6B"
COLOR_SUCCESS = "#4CD97B"
COLOR_BTN_BG = "#22232A"
COLOR_BTN_ACTIVE = "#2a2b30"


class IndexingApp:
    """
    Main application class for the Indexing API Tool.
    Handles the GUI setup and API interactions.
    """

    def __init__(self, root):
        """
        Initialize the application UI.
        
        Args:
            root (tk.Tk): The root tkinter window.
        """
        self.root = root
        root.title("Indexing API Tool")
        root.geometry("820x520")
        root.configure(bg=COLOR_BG)
        root.resizable(False, False)

        # Fonts
        self.font_h1 = font.Font(family="Segoe UI", size=12, weight="bold")
        self.font_h2 = font.Font(family="Segoe UI", size=10, weight="bold")
        self.font_body = font.Font(family="Segoe UI", size=10)

        self._setup_ui()
        
        # Bindings
        root.bind("<Return>", lambda e: self.on_send())

    def _setup_ui(self):
        """Constructs the user interface widgets."""
        # Main container
        container = tk.Frame(self.root, bg=COLOR_BG)
        container.pack(fill="both", expand=True, padx=16, pady=12)

        # --- Header ---
        top_frame = tk.Frame(container, bg=COLOR_PANEL, bd=0, relief="flat")
        top_frame.pack(fill="x", padx=4, pady=(0, 10))

        title = tk.Label(top_frame, text="Indexing API Tool", bg=COLOR_PANEL, fg=COLOR_TEXT, font=self.font_h1)
        title.grid(row=0, column=0, sticky="w", padx=12, pady=12)

        subtitle = tk.Label(
            top_frame, 
            text="Easily submit or remove URLs from Google Search Index", 
            bg=COLOR_PANEL, 
            fg=COLOR_MUTED, 
            font=self.font_body
        )
        subtitle.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 12))

        # --- Form Area ---
        form_frame = tk.Frame(container, bg=COLOR_BG)
        form_frame.pack(fill="x", padx=2, pady=(0, 8))

        # Service Account JSON Input
        lbl_json = tk.Label(form_frame, text="Service Account JSON File:", bg=COLOR_BG, fg=COLOR_TEXT, font=self.font_h2)
        lbl_json.grid(row=0, column=0, sticky="w", padx=(6, 4), pady=(2, 2))

        self.json_path_var = tk.StringVar()
        
        entry_json = tk.Entry(
            form_frame, 
            textvariable=self.json_path_var, 
            bg=COLOR_INPUT_BG, 
            fg=COLOR_TEXT, 
            insertbackground=COLOR_TEXT, 
            relief="flat", 
            width=70, 
            font=self.font_body
        )
        entry_json.grid(row=1, column=0, padx=(6, 4), pady=6, sticky="w")

        btn_browse = tk.Button(
            form_frame, 
            text="Browse", 
            command=self.browse_json, 
            bg=COLOR_BTN_BG, 
            fg=COLOR_TEXT, 
            activebackground=COLOR_BTN_ACTIVE, 
            relief="flat", 
            padx=12
        )
        btn_browse.grid(row=1, column=1, padx=(6, 10), sticky="w")

        # URL Input
        lbl_url = tk.Label(form_frame, text="URL to Publish/Remove:", bg=COLOR_BG, fg=COLOR_TEXT, font=self.font_h2)
        lbl_url.grid(row=2, column=0, sticky="w", padx=(6, 4), pady=(8, 2))

        self.url_var = tk.StringVar()
        entry_url = tk.Entry(
            form_frame, 
            textvariable=self.url_var, 
            bg=COLOR_INPUT_BG, 
            fg=COLOR_TEXT, 
            insertbackground=COLOR_TEXT, 
            relief="flat", 
            width=104, 
            font=self.font_body
        )
        entry_url.grid(row=3, column=0, columnspan=2, padx=6, pady=6, sticky="w")

        # Action Selection
        action_frame = tk.Frame(form_frame, bg=COLOR_BG)
        action_frame.grid(row=4, column=0, columnspan=2, sticky="w", padx=6, pady=(8, 4))

        lbl_action = tk.Label(action_frame, text="Action:", bg=COLOR_BG, fg=COLOR_TEXT, font=self.font_h2)
        lbl_action.pack(side="left", padx=(0, 10))

        self.action_var = tk.StringVar(value="URL_UPDATED")
        
        r1 = tk.Radiobutton(
            action_frame, 
            text="Publish / Update", 
            variable=self.action_var, 
            value="URL_UPDATED", 
            bg=COLOR_BG, 
            fg=COLOR_TEXT, 
            selectcolor=COLOR_PANEL, 
            activebackground=COLOR_BG, 
            font=self.font_body
        )
        r1.pack(side="left", padx=(0, 12))
        
        r2 = tk.Radiobutton(
            action_frame, 
            text="Remove", 
            variable=self.action_var, 
            value="URL_REMOVED", 
            bg=COLOR_BG, 
            fg=COLOR_TEXT, 
            selectcolor=COLOR_PANEL, 
            activebackground=COLOR_BG, 
            font=self.font_body
        )
        r2.pack(side="left")

        # Controls
        controls_frame = tk.Frame(form_frame, bg=COLOR_BG)
        controls_frame.grid(row=5, column=0, columnspan=2, sticky="w", padx=6, pady=(8, 6))

        self.send_btn = tk.Button(
            controls_frame, 
            text="Send Request", 
            command=self.on_send, 
            bg=COLOR_ACCENT, 
            fg="#fff", 
            activebackground="#574CFF", 
            relief="flat", 
            padx=18, 
            pady=6, 
            font=self.font_h2
        )
        self.send_btn.pack(side="left")

        self.status_var = tk.StringVar(value="Ready")
        self.status_label = tk.Label(controls_frame, textvariable=self.status_var, bg=COLOR_BG, fg=COLOR_MUTED, font=self.font_body)
        self.status_label.pack(side="left", padx=(12, 0))

        # --- Result Panel ---
        result_panel = tk.Frame(container, bg=COLOR_PANEL)
        result_panel.pack(fill="both", expand=True, padx=4, pady=(6, 6))

        lbl_resp = tk.Label(result_panel, text="Response Output:", bg=COLOR_PANEL, fg=COLOR_TEXT, font=self.font_h2)
        lbl_resp.pack(anchor="w", padx=12, pady=(10, 4))

        self.output_text = scrolledtext.ScrolledText(
            result_panel, 
            bg="#07080B", 
            fg=COLOR_TEXT, 
            insertbackground=COLOR_TEXT, 
            wrap="none", 
            font=("Consolas", 10), 
            relief="flat"
        )
        self.output_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # --- Footer ---
        footer_frame = tk.Frame(container, bg=COLOR_BG)
        footer_frame.pack(fill="x", padx=6, pady=(0, 6))

        tip_text = "Tip: Keep your JSON key file secure. Do not commit it to public repositories."
        self.tip_label = tk.Label(footer_frame, text=tip_text, bg=COLOR_BG, fg=COLOR_MUTED, font=self.font_body)
        self.tip_label.pack(side="left", padx=(4, 0))

        # Right-side actions
        right_actions = tk.Frame(footer_frame, bg=COLOR_BG)
        right_actions.pack(side="right", padx=6)

        btn_copy = tk.Button(
            right_actions, 
            text="Copy URL", 
            command=self.copy_url, 
            bg=COLOR_BTN_BG, 
            fg=COLOR_TEXT, 
            relief="flat", 
            padx=10
        )
        btn_copy.pack(side="left", padx=(0, 8))
        
        btn_clear = tk.Button(
            right_actions, 
            text="Clear Log", 
            command=self.clear_output, 
            bg=COLOR_BTN_BG, 
            fg=COLOR_TEXT, 
            relief="flat", 
            padx=10
        )
        btn_clear.pack(side="left")

    def browse_json(self):
        """Open file dialog to select the JSON key file."""
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if path:
            self.json_path_var.set(path)

    def set_status(self, text, color=None):
        """Update the status label text and color."""
        self.status_var.set(text)
        self.status_label.config(fg=color if color else COLOR_MUTED)
        self.root.update_idletasks()

    def copy_url(self):
        """Copy the current URL to the clipboard."""
        val = self.url_var.get().strip()
        if val:
            self.root.clipboard_clear()
            self.root.clipboard_append(val)
            self.set_status("URL copied to clipboard", COLOR_SUCCESS)
        else:
            self.set_status("No URL to copy", COLOR_ERROR)

    def clear_output(self):
        """Clear the response output text area."""
        self.output_text.delete(1.0, tk.END)
        self.set_status("Output cleared")

    def on_send(self):
        """Handle the Send button click (starts a thread)."""
        t = threading.Thread(target=self.send_request, daemon=True)
        t.start()

    def create_authed_session(self, sa_file):
        """
        Create an authorized session using the service account file.
        
        Args:
            sa_file (str): Path to the service account JSON file.
            
        Returns:
            AuthorizedSession: An authorized HTTP session.
        """
        creds = service_account.Credentials.from_service_account_file(sa_file, scopes=SCOPES)
        return AuthorizedSession(creds)

    def send_request(self):
        """Execute the API request in a background thread."""
        self.send_btn.config(state="disabled")
        self.output_text.delete(1.0, tk.END)
        
        json_path = self.json_path_var.get().strip()
        url = self.url_var.get().strip()
        action = self.action_var.get()

        # Validation
        if not json_path or not os.path.isfile(json_path):
            messagebox.showerror("Configuration Error", "Please select a valid Service Account JSON file.")
            self.set_status("Invalid JSON file", COLOR_ERROR)
            self.send_btn.config(state="normal")
            return
            
        if not url:
            messagebox.showerror("Input Error", "Please enter a URL to index.")
            self.set_status("URL missing", COLOR_ERROR)
            self.send_btn.config(state="normal")
            return

        # Authentication
        try:
            self.set_status("Authenticating...")
            session = self.create_authed_session(json_path)
        except Exception as e:
            messagebox.showerror("Authentication Error", f"Failed to authenticate:\n{e}")
            self.set_status("Authentication failed", COLOR_ERROR)
            self.send_btn.config(state="normal")
            return

        # API Request
        body = {"url": url, "type": action}
        try:
            self.set_status("Sending request...")
            resp = session.post(INDEXING_ENDPOINT, json=body, timeout=30)
            
            try:
                data = resp.json()
                pretty_response = json.dumps(data, indent=2)
            except Exception:
                pretty_response = resp.text
                
            self.output_text.insert(tk.END, f"HTTP Status: {resp.status_code}\n\n{pretty_response}")
            
            if resp.status_code == 200:
                self.set_status(f"Success: {resp.status_code}", COLOR_SUCCESS)
            else:
                self.set_status(f"Error: {resp.status_code}", COLOR_ERROR)
                
        except Exception as e:
            self.output_text.insert(tk.END, f"Request failed:\n{e}")
            self.set_status("Request failed", COLOR_ERROR)
        finally:
            self.send_btn.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    app = IndexingApp(root)
    root.mainloop()

