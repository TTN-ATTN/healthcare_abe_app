#!/usr/bin/env python3.11
import tkinter as tk
from tkinter import messagebox, ttk
import sys
import os
import csv

SRC_DIR = os.path.dirname(os.path.abspath(__file__)) 
DATA_DIR = os.path.join(os.path.dirname(SRC_DIR), "data")
print(f"Source Directory: {SRC_DIR}")
print(f"Data Directory: {DATA_DIR}")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from user_management.user_service import verify_user, create_user_file_if_not_exists, USER_DATA_FILE

class HealthcareApp:
    def __init__(self, root=None):
        # Initialize the main application window
        if root is None:
            self.root = tk.Tk()
        else:
            self.root = root
            
        self.root.title("Healthcare System Login")
        self.root.geometry("400x250")
        self.root.resizable(True, True)
        
        # This will hold our current active window after login
        self.current_window = None
        
        create_user_file_if_not_exists()

        # Configure styles
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TLabel", padding=5, font=("Helvetica", 10))
        style.configure("TEntry", padding=5, font=("Helvetica", 10))
        style.configure("TButton", padding=5, font=("Helvetica", 10, "bold"))

        # Create login frame
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
        login_button = ttk.Button(login_frame, text="Login", command=self.attempt_login)
        login_button.grid(row=2, column=0, columnspan=2, pady=20)

        login_frame.columnconfigure(1, weight=1)

    def get_user_attributes(self, username):
        try:
            with open(USER_DATA_FILE, "r", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row["username"] == username:
                        return row
        except FileNotFoundError:
            print("User data file not found.")
        return None

    def attempt_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Login Failed", "Username and Password cannot be empty.")
            return

        role = verify_user(username, password)

        if role:
            user_attributes = self.get_user_attributes(username)
            self.root.withdraw()  # Hide the login window instead of destroying it
            self.open_role_window(username, role, user_attributes)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")
            self.password_entry.delete(0, tk.END)

    def open_role_window(self, username, role, attributes):
        # Create a new top-level window for the role dashboard
        self.current_window = tk.Toplevel()
        self.current_window.title(f"{role} Dashboard - {username}")
        self.current_window.geometry("800x600")
        self.current_window.resizable(True, True)
        
        # Set protocol for when window is closed
        self.current_window.protocol("WM_DELETE_WINDOW", lambda: self.logout(self.current_window))

        main_frame = ttk.Frame(self.current_window, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")

        self.current_window.grid_rowconfigure(0, weight=1)
        self.current_window.grid_columnconfigure(0, weight=1)

        # Welcome message
        ttk.Label(main_frame, text=f"Welcome, {username}!", font=("Helvetica", 16, "bold")).grid(
            row=0, column=0, columnspan=2, pady=10)
        ttk.Label(main_frame, text=f"You are logged in as: {role}", font=("Helvetica", 12)).grid(
            row=1, column=0, columnspan=2, pady=5)

        # Display additional attributes
        attr_row = 2
        for key, value in attributes.items():
            if key not in ["username", "salt", "hashed_password", "role"]:
                display_key = key.replace("_", " ").title()
                ttk.Label(main_frame, text=f"{display_key}: {value}", font=("Helvetica", 10)).grid(
                    row=attr_row, column=0, columnspan=2, sticky="w", padx=5)
                attr_row += 1

        # Content frame for role-specific buttons
        content_frame = ttk.Frame(main_frame, relief="sunken", borderwidth=2, padding="10")
        content_frame.grid(row=attr_row, column=0, columnspan=2, sticky="nsew", pady=20)
        main_frame.grid_rowconfigure(attr_row, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)

        # Role-specific functionality
        if role == "Doctor":
            ttk.Button(content_frame, text="View Patient Records", 
                      command=self.view_patient_records).grid(row=0, column=0, pady=5)
            ttk.Button(content_frame, text="Manage Appointments (Placeholder)").grid(row=1, column=0, pady=5)
        elif role == "Researcher":
            ttk.Button(content_frame, text="Access Research Data", 
                      command=self.access_research_data).grid(row=0, column=0, pady=5)
        elif role == "Admin":
            ttk.Button(content_frame, text="Manage Users (Placeholder)").grid(row=0, column=0, pady=5)
        else:
            ttk.Label(content_frame, text="No specific functionalities defined for this role yet.").grid(
                row=0, column=0)

        # Logout button
        logout_frame = ttk.Frame(main_frame)
        logout_frame.grid(row=attr_row + 1, column=0, columnspan=2, pady=10)
        ttk.Button(logout_frame, text="Logout", 
                  command=lambda: self.logout(self.current_window)).grid(row=0, column=0)

    def view_patient_records(self):
        try:
            patient_records_file = os.path.join(DATA_DIR, "patient_records.txt")
            with open(patient_records_file) as f:
                records = f.read()
            self.display_data_window("Patient Records", records)
        except FileNotFoundError:
            messagebox.showerror("Error", "Patient records file not found.")

    def access_research_data(self):
        try:
            research_file = os.path.join(DATA_DIR, "research_data.txt")
            with open(research_file, "r") as f:
                data = f.read()
            self.display_data_window("Research Data", data)
        except FileNotFoundError:
            messagebox.showerror("Error", "Research data file not found.")

    def display_data_window(self, title, data):
        data_window = tk.Toplevel(self.current_window)
        data_window.title(title)
        data_window.geometry("600x500")
        
        # Add text widget with scrollbar
        text_frame = ttk.Frame(data_window)
        text_frame.pack(expand=True, fill="both", padx=10, pady=10)
        
        text_scroll = ttk.Scrollbar(text_frame)
        text_scroll.pack(side="right", fill="y")
        
        text_area = tk.Text(text_frame, wrap="word", yscrollcommand=text_scroll.set)
        text_area.pack(expand=True, fill="both")
        
        text_scroll.config(command=text_area.yview)
        text_area.insert(tk.END, data)
        text_area.config(state="disabled")

    def logout(self, window_to_close):
        window_to_close.destroy()
        if hasattr(self, 'root') and self.root.winfo_exists():
            self.root.deiconify()  # Show the login window again
        else:
            # If root window was destroyed, create a new one
            self.root = tk.Tk()
            self.__init__(self.root)
            self.root.mainloop()

if __name__ == "__main__":
    main_root = tk.Tk()
    app = HealthcareApp(main_root)
    main_root.mainloop()