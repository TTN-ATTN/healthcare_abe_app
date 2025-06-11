import tkinter as tk
from tkinter import ttk

class DashboardUI:
    def __init__(self, root, username, role, button_callbacks):
        self.root = root
        self.username = username
        self.role = role
        self.button_callbacks = button_callbacks
        self.setup_ui()
        
    def setup_ui(self):
        self.root.title(f"{self.role} Dashboard - {self.username}")
        self.root.geometry("800x600")
        
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Welcome message
        ttk.Label(main_frame, text=f"Welcome, {self.username}!", 
                 font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        ttk.Label(main_frame, text=f"You are logged in as: {self.role}", 
                 font=("Helvetica", 12)).grid(row=1, column=0, columnspan=2, pady=5)

        # Content frame
        self.content_frame = ttk.Frame(main_frame, relief="sunken", borderwidth=2, padding="10")
        self.content_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=20)
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="SEARCH", 
                  command=self.button_callbacks['search']).grid(
                      row=0, column=0, padx=10, pady=10, ipadx=10, ipady=5)
        
        ttk.Button(button_frame, text="UPLOAD", 
                  command=self.button_callbacks['upload']).grid(
                      row=0, column=2, padx=10, pady=10, ipadx=10, ipady=5)
                  
        if self.role == 'admin':
            ttk.Button(button_frame, text="ADD USERS", 
                    command=self.button_callbacks['add_user']).grid(
                        row=0, column=3, padx=10, pady=10, ipadx=10, ipady=5)

        # Logout button
        logout_frame = ttk.Frame(main_frame)
        logout_frame.grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(logout_frame, text="Logout", 
                  command=self.button_callbacks['logout']).grid(row=0, column=0)