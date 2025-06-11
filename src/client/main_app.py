import tkinter as tk
from tkinter import messagebox
from ui.login import LoginUI
from ui.dashboard import DashboardUI
from ui.search import SearchUI
from ui.upload import UploadUI
import requests
import json

AUTHORITY_SERVER = "http://127.0.0.1:5000"
STORAGE_SERVER = "http://127.0.0.1:8000"

class HealthcareApp:
    def __init__(self):
        self.root = tk.Tk()
        self.current_user = None
        self.current_role = None
        self.current_token = None
        self.current_ui = None
        self.dashboard_ui = None
        self.show_login()
    
    def show_login(self):
        self.clear_current_ui()
        self.login_ui = LoginUI(self.root, self.handle_login)
    
    def handle_login(self, username, password):
        try:
            login_response = requests.post(
                f"{AUTHORITY_SERVER}/login",
                data={'username': username, 'password': password},
                timeout=5
            )
            
            if login_response.status_code == 200:
                user_data = login_response.json()
                self.current_user = username
                self.current_role = self.determine_role(user_data.get('attributes', []))
                
                # Get JWT token
                token_response = requests.post(
                    f"{AUTHORITY_SERVER}/token",
                    json={
                        'user_id': user_data.get('user_id'),
                        'attributes': user_data.get('attributes', [])
                    },
                    headers={'Content-Type': 'application/json'},
                    timeout=15
                )
                
                if token_response.status_code == 200:
                    self.current_token = token_response.json().get('token')
                    self.show_dashboard()
                else:
                    messagebox.showerror("Login Failed", "Token generation failed")
            else:
                messagebox.showerror("Login Failed", "Invalid credentials")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
    
    def determine_role(self, attributes):
        """Determine the highest privilege role from attributes"""
        role_priority = ['admin', 'doctor', 'nurse', 'researcher', 'patient']
        for role in role_priority:
            if role in attributes:
                return role
        return 'patient'  # default role
    
    def show_dashboard(self):
        """Display the main dashboard"""
        self.clear_current_ui()
        
        button_callbacks = {
            'search': self.show_search,
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
        else:
            messagebox.showerror("Error", "Dashboard not properly initialized")
    
    def show_upload(self):
        """Display the upload interface"""
        if self.dashboard_ui and hasattr(self.dashboard_ui, 'content_frame'):
            try:
                self.upload_ui = UploadUI(
                    self.dashboard_ui.content_frame, 
                    self.handle_upload,
                )
            except Exception as e:
                messagebox.showerror("Upload UI Error", f"Failed to load upload interface: {str(e)}")
        else:
            messagebox.showerror("Error", "Dashboard not properly initialized")
    
    def handle_search(self, search_params):
        """Handle search functionality"""
        try:
            if not self.current_token:
                messagebox.showerror("Error", "Not authenticated")
                return
                
            # Prepare request to storage server
            headers = {
                'Authorization': f'Bearer {self.current_token}',
                'Content-Type': 'application/json'
            }
            
            # Convert search parameters to query string
            params = {
                'user_id': search_params.get('user_id', ''),
                'name': search_params.get('name', ''),
                'record_type': search_params.get('record_type', 'health_record')
            }
            
            response = requests.get(
                f"{STORAGE_SERVER}/api/{params['record_type']}",
                headers=headers,
                params=params,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                messagebox.showinfo("Search Results", 
                                  f"Found {data.get('count', 0)} records")
                # Here you would typically display the results in the UI
            else:
                messagebox.showerror("Search Failed", 
                                   f"Server returned {response.status_code}: {response.text[:200]}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
    
    def handle_upload(self, upload_params):
        """Handle file upload functionality"""
        messagebox.showinfo("Info", "Upload feature not implemented yet")
    
    def handle_logout(self):
        try:
            if self.current_token:
                requests.post(
                    f"{AUTHORITY_SERVER}/logout",
                    headers={'Authorization': f'Bearer {self.current_token}'},
                    timeout=5
                )
        except:
            pass  # Even if logout fails, we'll clear the session
        
        self.current_user = None
        self.current_role = None
        self.current_token = None
        self.dashboard_ui = None  
        self.show_login()
    
    def clear_current_ui(self):
        try:
            for widget in self.root.winfo_children():
                widget.destroy()
        except Exception as e:
            print(f"Error clearing UI: {e}")
    
    def run(self):
        try:
            self.root.mainloop()
        except Exception as e:
            print(f"Application error: {e}")

if __name__ == "__main__":
    try:
        app = HealthcareApp()
        app.run()
    except Exception as e:
        print(f"Failed to start application: {e}")