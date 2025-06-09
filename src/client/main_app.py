import tkinter as tk
from tkinter import messagebox
from ui.login import LoginUI
from ui.dashboard import DashboardUI
from ui.search import SearchUI
from ui.view import ViewUI
from ui.upload import UploadUI

class HealthcareApp:
    def __init__(self):
        self.root = tk.Tk()
        self.current_user = None
        self.current_role = None
        self.current_ui = None
        self.dashboard_ui = None  # Initialize dashboard_ui
        self.show_login()
    
    def show_login(self):
        self.clear_current_ui()
        self.login_ui = LoginUI(self.root, self.handle_login)
    
    def handle_login(self, username, password, role):
        if self.authenticate_user(username, password, role):
            self.current_user = username
            self.current_role = role
            self.show_dashboard()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials")
    
    def authenticate_user(self, username, password, role):
        return username and password and role
    
    def show_dashboard(self):
        """Display the main dashboard"""
        self.clear_current_ui()
        
        # Define button callbacks for dashboard
        button_callbacks = {
            'search': self.show_search,
            'view': self.show_view,
            'upload': self.show_upload,
            'logout': self.handle_logout
        }
        
        try:
            self.dashboard_ui = DashboardUI(
                self.root, 
                self.current_user, 
                self.current_role, 
                button_callbacks
            )
            self.current_ui = self.dashboard_ui
        except Exception as e:
            messagebox.showerror("Dashboard Error", f"Failed to load dashboard: {str(e)}")
            print(f"Dashboard creation error: {e}")  # For debugging
    
    def show_search(self):
        """Display the search interface"""
        if self.dashboard_ui and hasattr(self.dashboard_ui, 'content_frame'):
            try:
                self.search_ui = SearchUI(
                    self.dashboard_ui.content_frame, 
                    self.handle_search
                )
            except Exception as e:
                messagebox.showerror("Search UI Error", f"Failed to load search interface: {str(e)}")
                print(f"Search UI error: {e}")  # For debugging
        else:
            messagebox.showerror("Error", "Dashboard not properly initialized")
    
    def show_view(self):
        """Display the view records interface"""
        if self.dashboard_ui and hasattr(self.dashboard_ui, 'content_frame'):
            try:
                self.view_ui = ViewUI(
                    self.dashboard_ui.content_frame, 
                    self.handle_view
                )
            except Exception as e:
                messagebox.showerror("View UI Error", f"Failed to load view interface: {str(e)}")
                print(f"View UI error: {e}")  # For debugging
        else:
            messagebox.showerror("Error", "Dashboard not properly initialized")
    
    def show_upload(self):
        """Display the upload interface"""
        if self.dashboard_ui and hasattr(self.dashboard_ui, 'content_frame'):
            try:
                self.upload_ui = UploadUI(
                    self.dashboard_ui.content_frame, 
                    self.handle_upload,
                    self.handle_browse
                )
            except Exception as e:
                messagebox.showerror("Upload UI Error", f"Failed to load upload interface: {str(e)}")
                print(f"Upload UI error: {e}")  # For debugging
        else:
            messagebox.showerror("Error", "Dashboard not properly initialized")
    
    def handle_search(self, search_params):
        """Handle search functionality"""
        try:
            user_id = search_params.get('user_id', '')
            name = search_params.get('name', '')
            record_type = search_params.get('record_type', '')
            results = self.perform_search(user_id, name, record_type)
            messagebox.showinfo("Search Results", f"Found {len(results)} records")
            
        except Exception as e:
            messagebox.showerror("Search Error", f"Search failed: {str(e)}")
    
    def handle_view(self, view_params):
        try:
            user_id = view_params.get('user_id', '')
            record_type = view_params.get('record_type', '')
            records = self.get_user_records(user_id, record_type)
            messagebox.showinfo("View Records", f"Displaying records for user: {user_id}")
            
        except Exception as e:
            messagebox.showerror("View Error", f"Failed to load records: {str(e)}")
    
    def handle_upload(self, upload_params):
        """Handle file upload functionality"""
        try:
            user_id = upload_params.get('user_id', '')
            record_type = upload_params.get('record_type', '')
            file_path = upload_params.get('file_path', '')
            success = self.upload_file(user_id, record_type, file_path)
            
            if success:
                messagebox.showinfo("Upload Success", "File uploaded successfully")
            else:
                messagebox.showerror("Upload Failed", "Failed to upload file")
                
        except Exception as e:
            messagebox.showerror("Upload Error", f"Upload failed: {str(e)}")
    
    def handle_browse(self):
        """Handle file browse functionality for upload"""
        try:
            from tkinter import filedialog
            
            file_path = filedialog.askopenfilename(
                title="Select file to upload",
                filetypes=[
                    ("All files", "*.*"),
                    ("PDF files", "*.pdf"),
                    ("Image files", "*.jpg *.jpeg *.png *.gif"),
                    ("Document files", "*.doc *.docx *.txt")
                ]
            )
            
            return file_path
        except Exception as e:
            messagebox.showerror("Browse Error", f"Failed to open file browser: {str(e)}")
            return ""
    
    def handle_logout(self):
        self.current_user = None
        self.current_role = None
        self.dashboard_ui = None  # Reset dashboard_ui
        self.show_login()
    
    def clear_current_ui(self):
        try:
            for widget in self.root.winfo_children():
                widget.destroy()
        except Exception as e:
            print(f"Error clearing UI: {e}")
    
    # Database/Backend methods (implement according to your needs)
    def perform_search(self, user_id, name, record_type):
        # Placeholder implementation
        return []
    
    def get_user_records(self, user_id, record_type):
        # Placeholder implementation
        return []
    
    def upload_file(self, user_id, record_type, file_path):
        # Placeholder implementation
        return True
    
    def run(self):
        try:
            self.root.mainloop()
        except Exception as e:
            print(f"Application error: {e}")

# Application entry point
if __name__ == "__main__":
    try:
        app = HealthcareApp()
        app.run()
    except Exception as e:
        print(f"Failed to start application: {e}")
