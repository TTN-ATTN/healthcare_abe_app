import tkinter as tk
from tkinter import ttk

class ViewUI:
    def __init__(self, parent_frame, view_callback):
        self.parent = parent_frame
        self.view_callback = view_callback
        self.setup_ui()
        
    def setup_ui(self):
        for widget in self.parent.winfo_children():
            widget.destroy()
        
        view_frame = ttk.Frame(self.parent)
        view_frame.pack(expand=True, fill="both", padx=10, pady=10)
        
        ttk.Label(view_frame, text="User ID").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.user_id_entry = ttk.Entry(view_frame, width=30)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(view_frame, text="Record Type").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.record_type_var = tk.StringVar()
        self.record_type_dropdown = ttk.Combobox(
            view_frame, 
            textvariable=self.record_type_var,
            values=["health_record", "financial_record", "user_record"],
            state="readonly",
            width=27
        )
        self.record_type_dropdown.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.record_type_dropdown.current(0)

        view_button = ttk.Button(view_frame, text="View Records", command=self.on_view)
        view_button.grid(row=2, column=0, columnspan=2, pady=10)
        
        clear_button = ttk.Button(view_frame, text="Clear", command=self.clear_fields)
        clear_button.grid(row=3, column=0, columnspan=2, pady=5)
        
        view_frame.columnconfigure(1, weight=1)
    
    def on_view(self):
        params = {
            'user_id': self.user_id_entry.get(),
            'record_type': self.record_type_var.get()
        }
        self.view_callback(params)
    
    def clear_fields(self):
        self.user_id_entry.delete(0, tk.END)
        self.record_type_dropdown.current(0)