#!/usr/bin/env python3.11
import tkinter as tk
from tkinter import messagebox, ttk
import sys
import os

SRC_DIR = os.path.dirname(os.path.abspath(__file__)) 
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from user_management.user_service import verify_user, ROLES, create_user_file_if_not_exists

class HealthcareApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Healthcare System Login")
        self.root.geometry("400x250")
        self.root.resizable(True, True)

        create_user_file_if_not_exists()

        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("TLabel", padding=5, font=("Helvetica", 10))
        style.configure("TEntry", padding=5, font=("Helvetica", 10))
        style.configure("TButton", padding=5, font=("Helvetica", 10, "bold"))

        login_frame = ttk.Frame(self.root, padding="20 20 20 20")
        login_frame.grid(row=0, column=0, sticky="nsew")

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=10, sticky="w")
        self.username_entry = ttk.Entry(login_frame, width=30)
        self.username_entry.grid(row=0, column=1, padx=5, pady=10, sticky="ew")
        self.username_entry.focus()

        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=10, sticky="w")
        self.password_entry = ttk.Entry(login_frame, show="*", width=30)
        self.password_entry.grid(row=1, column=1, padx=5, pady=10, sticky="ew")

        login_button = ttk.Button(login_frame, text="Login", command=self.attempt_login)
        login_button.grid(row=2, column=0, columnspan=2, pady=20)

        login_frame.columnconfigure(1, weight=1)

    def attempt_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Login Failed", "Username and Password cannot be empty.")
            return

        role = verify_user(username, password)

        if role:
            self.root.destroy()
            self.open_role_window(username, role)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")
            self.password_entry.delete(0, tk.END)

    def open_role_window(self, username, role):
        role_window = tk.Tk()
        role_window.title(f"{role} Dashboard - {username}")
        role_window.geometry("600x400")
        role_window.resizable(True, True)

        main_frame = ttk.Frame(role_window, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")

        role_window.grid_rowconfigure(0, weight=1)
        role_window.grid_columnconfigure(0, weight=1)

        ttk.Label(main_frame, text=f"Welcome, {username}!", font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        ttk.Label(main_frame, text=f"You are logged in as: {role}", font=("Helvetica", 12)).grid(row=1, column=0, columnspan=2, pady=5)

        content_frame = ttk.Frame(main_frame, relief="sunken", borderwidth=2, padding="10")
        content_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=20)
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)

        if role == "Doctor":
            ttk.Button(content_frame, text="View Patient Records (Placeholder)").grid(row=0, column=0, pady=5)
            ttk.Button(content_frame, text="Manage Appointments (Placeholder)").grid(row=1, column=0, pady=5)
        else:
            ttk.Label(content_frame, text="No specific functionalities defined for this role yet.").grid(row=0, column=0)

        logout_frame = ttk.Frame(main_frame)
        logout_frame.grid(row=3, column=0, columnspan=2, pady=10)
        logout_button = ttk.Button(logout_frame, text="Logout", command=lambda: self.logout(role_window))
        logout_button.grid(row=0, column=0)

    def logout(self, current_window):
        current_window.destroy()
        new_root = tk.Tk()
        app = HealthcareApp(new_root)
        new_root.mainloop()

if __name__ == "__main__":
    main_root = tk.Tk()
    app = HealthcareApp(main_root)
    main_root.mainloop()
