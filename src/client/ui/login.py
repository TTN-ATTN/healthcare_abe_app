import tkinter as tk
from tkinter import ttk

class LoginUI:
    def __init__(self, root, login_callback):
        self.root = root
        self.login_callback = login_callback
        self.setup_ui()
        
    def setup_ui(self):
        self.root.title("Healthcare System Login")
        self.root.geometry("400x250")
        
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TLabel", padding=5, font=("Helvetica", 10))
        style.configure("TEntry", padding=5, font=("Helvetica", 10))
        style.configure("TButton", padding=5, font=("Helvetica", 10, "bold"))

        login_frame = ttk.Frame(self.root, padding="20 20 20 20")
        login_frame.grid(row=0, column=0, sticky="nsew")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Username field
        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=10, sticky="w")
        self.username_entry = ttk.Entry(login_frame, width=30)
        self.username_entry.grid(row=0, column=1, padx=5, pady=10, sticky="ew")
        self.username_entry.focus()

        # Password field
        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=10, sticky="w")
        self.password_entry = ttk.Entry(login_frame, show="*", width=30)
        self.password_entry.grid(row=1, column=1, padx=5, pady=10, sticky="ew")

        # Login button
        login_button = ttk.Button(login_frame, text="Login", command=self.on_login)
        login_button.grid(row=2, column=0, columnspan=2, pady=20)
        login_frame.columnconfigure(1, weight=1)
    
    def on_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.login_callback(username, password, "default_role")
