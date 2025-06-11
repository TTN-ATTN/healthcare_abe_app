import tkinter as tk
from tkinter import ttk

class UploadUI:
    def __init__(self, parent_frame, upload_callback):
        self.parent = parent_frame
        self.upload_callback = upload_callback
        self.setup_ui()
        
    def setup_ui(self):
        for widget in self.parent.winfo_children():
            widget.destroy()
        
        upload_frame = ttk.Frame(self.parent)
        upload_frame.pack(expand=True, fill="both", padx=10, pady=10)
        
        ttk.Label(upload_frame, text="Patient user_id").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.user_id_entry = ttk.Entry(upload_frame, width=30)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Name field
        ttk.Label(upload_frame, text="Name").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.name_entry = ttk.Entry(upload_frame, width=30)
        self.name_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(upload_frame, text="Record Type").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.record_type_var = tk.StringVar()
        self.record_type_dropdown = ttk.Combobox(
            upload_frame, 
            textvariable=self.record_type_var,
            values=["health_record", "financial_record", "user_record"],
            state="readonly",
            width=27
        )
        self.record_type_dropdown.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.record_type_dropdown.current(0)

        upload_button = ttk.Button(upload_frame, text="Upload Records", command=self.on_upload)
        upload_button.grid(row=3, column=0, columnspan=3, pady=10)
        
        clear_button = ttk.Button(upload_frame, text="Clear", command=self.clear_fields)
        clear_button.grid(row=4, column=0, columnspan=3, pady=5)
        
        upload_frame.columnconfigure(1, weight=1)
    
    def on_upload(self):
        params = {
            'user_id': self.user_id_entry.get(),
            'record_type': self.record_type_var.get(),
        }
        self.upload_callback(params)
    
    def clear_fields(self):
        self.user_id_entry.delete(0, tk.END)
        self.record_type_dropdown.current(0)


class UpdateUI:
    def __init__(self, parent_frame, update_callback):
        self.parent = parent_frame
        self.update_callback = update_callback
        self.setup_ui()
        
    def setup_ui(self):
        for widget in self.parent.winfo_children():
            widget.destroy()
        
        update_frame = ttk.Frame(self.parent)
        update_frame.pack(expand=True, fill="both", padx=10, pady=10)
        
        ttk.Label(update_frame, text="User user_id").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.user_id_entry = ttk.Entry(update_frame, width=30)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(update_frame, text="Record Type").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.record_type_var = tk.StringVar()
        self.record_type_dropdown = ttk.Combobox(
            update_frame, 
            textvariable=self.record_type_var,
            values=["health_record", "financial_record", "user_record"],
            state="readonly",
            width=27
        )
        self.record_type_dropdown.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.record_type_dropdown.current(0)
        
        ttk.Label(update_frame, text="Record user_id").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.record_id_entry = ttk.Entry(update_frame, width=30)
        self.record_id_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(update_frame, text="Update Data").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.update_data_text = tk.Text(update_frame, height=5, width=30)
        self.update_data_text.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        
        update_button = ttk.Button(update_frame, text="Update Records", command=self.on_update)
        update_button.grid(row=4, column=0, columnspan=2, pady=10)
        
        clear_button = ttk.Button(update_frame, text="Clear", command=self.clear_fields)
        clear_button.grid(row=5, column=0, columnspan=2, pady=5)
        
        update_frame.columnconfigure(1, weight=1)
    
    def on_update(self):
        params = {
            'user_id': self.user_id_entry.get(),
            'record_type': self.record_type_var.get(),
            'record_id': self.record_id_entry.get(),
            'update_data': self.update_data_text.get("1.0", tk.END).strip()
        }
        self.update_callback(params)
    
    def clear_fields(self):
        self.user_id_entry.delete(0, tk.END)
        self.record_type_dropdown.current(0)
        self.record_id_entry.delete(0, tk.END)
        self.update_data_text.delete("1.0", tk.END)