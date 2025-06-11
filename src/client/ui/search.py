import tkinter as tk
from tkinter import ttk

class SearchUI:
    def __init__(self, parent_frame, search_callback):
        self.parent = parent_frame
        self.search_callback = search_callback
        self.setup_ui()
        
    def setup_ui(self):
        for widget in self.parent.winfo_children():
            widget.destroy()
        
        search_frame = ttk.Frame(self.parent)
        search_frame.pack(expand=True, fill="both", padx=10, pady=10)
        
        # User user_id field
        ttk.Label(search_frame, text="Patient user_id").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.user_id_entry = ttk.Entry(search_frame, width=30)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Name field
        ttk.Label(search_frame, text="Name").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.name_entry = ttk.Entry(search_frame, width=30)
        self.name_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        # Record type dropdown
        ttk.Label(search_frame, text="Record Type").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.record_type_var = tk.StringVar()
        self.record_type_dropdown = ttk.Combobox(
            search_frame, 
            textvariable=self.record_type_var,
            values=["health_record", "financial_record", "user_record"],
            state="readonly",
            width=27
        )
        self.record_type_dropdown.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.record_type_dropdown.current(0)

        search_button = ttk.Button(search_frame, text="Search", command=self.on_search)
        search_button.grid(row=3, column=0, columnspan=2, pady=10)
        
        clear_button = ttk.Button(search_frame, text="Clear", command=self.clear_fields)
        clear_button.grid(row=4, column=0, columnspan=2, pady=5)
        
        search_frame.columnconfigure(1, weight=1)
    
    def on_search(self):
        params = {
            'user_id': self.user_id_entry.get(),
            'name': self.name_entry.get(),
            'record_type': self.record_type_var.get()
        }
        self.search_callback(params)
    
    def clear_fields(self):
        self.user_id_entry.delete(0, tk.END)
        self.name_entry.delete(0, tk.END)
        self.record_type_dropdown.current(0)


