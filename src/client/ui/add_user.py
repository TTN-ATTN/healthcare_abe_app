import tkinter as tk
from tkinter import ttk

class AddUserUI:
    def __init__(self, parent_frame, add_user_callback):
        self.parent = parent_frame
        self.add_user_callback = add_user_callback
        self.setup_ui()
        
    def setup_ui(self):
        for widget in self.parent.winfo_children():
            widget.destroy()
        
        add_user_frame = ttk.Frame(self.parent)
        add_user_frame.pack(expand=True, fill="both", padx=10, pady=10)
        
        # User ID field
        ttk.Label(add_user_frame, text="User ID:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.user_id_entry = ttk.Entry(add_user_frame, width=30)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Username field
        ttk.Label(add_user_frame, text="Username:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.username_entry = ttk.Entry(add_user_frame, width=30)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        # Password field
        ttk.Label(add_user_frame, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = ttk.Entry(add_user_frame, show="*", width=30)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        
        # Role dropdown
        ttk.Label(add_user_frame, text="Role:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.role_var = tk.StringVar()
        self.role_dropdown = ttk.Combobox(
            add_user_frame, 
            textvariable=self.role_var,
            values=["admin", "doctor", "nurse", "researcher", "patient"],
            state="readonly",
            width=27
        )
        self.role_dropdown.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        self.role_dropdown.current(4)  # Default to patient
        
        # Attributes field
        ttk.Label(add_user_frame, text="Attributes (comma separated):").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.attributes_entry = ttk.Entry(add_user_frame, width=30)
        self.attributes_entry.grid(row=4, column=1, padx=5, pady=5, sticky="ew")
        
        # Add user button
        add_button = ttk.Button(add_user_frame, text="Add User", command=self.on_add_user)
        add_button.grid(row=5, column=0, columnspan=2, pady=10)
        
        # Clear button
        clear_button = ttk.Button(add_user_frame, text="Clear", command=self.clear_fields)
        clear_button.grid(row=6, column=0, columnspan=2, pady=5)
        
        add_user_frame.columnconfigure(1, weight=1)
    
    def on_add_user(self):
        attributes_text = self.attributes_entry.get()
        attributes = [attr.strip() for attr in attributes_text.split(",")] if attributes_text else []
        
        role = self.role_var.get()
        if role not in attributes:
            attributes.append(role)
            
        user_data = {
            'user_id': self.user_id_entry.get(),
            'username': self.username_entry.get(),
            'password': self.password_entry.get(),
            'attributes': attributes,
            'role': role
        }
        self.add_user_callback(user_data)
    
    def clear_fields(self):
        self.user_id_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.role_dropdown.current(4)
        self.attributes_entry.delete(0, tk.END)