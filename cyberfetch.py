import tkinter as tk
from tkinter import messagebox
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import ssl

# Suppress SSL certificate warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def fetch_url():
    url = url_entry.get()
    try:
        # Send HTTP GET request to the URL with SSL certificate validation
        response = requests.get(url, verify=True)
        
        # Print the response status code
        status_code_label.config(text=f"Status Code: {response.status_code}")
        
        if response.ok:
            # Print the content type of the response
            print(f"Content Type: {response.headers.get('content-type', 'N/A')}")
            
            # Check for security headers
            security_headers = response.headers.get('X-Content-Type-Options', ''), response.headers.get('X-Frame-Options', '')
            security_headers_info = "\n".join([f"{header}: {value}" for header, value in zip(("X-Content-Type-Options", "X-Frame-Options"), security_headers)])
            security_headers_label.config(text=security_headers_info)
            
            # Inspect response body for common security vulnerabilities
            response_body = response.text.lower()
            if "sql" in response_body or "sql injection" in response_body:
                messagebox.showwarning("Security Alert", "Potential SQL Injection Detected in Response Body!")
            if "xss" in response_body or "cross-site scripting" in response_body:
                messagebox.showwarning("Security Alert", "Potential Cross-Site Scripting (XSS) Detected in Response Body!")
            
            # Check for open redirect vulnerability
            if response.history:
                messagebox.showwarning("Security Alert", "Open Redirect Detected!")
            
            # Check for insecure direct object references (IDOR)
            if ".." in url:
                messagebox.showwarning("Security Alert", "Insecure Direct Object References (IDOR) Detected!")
            
            # Check for server-side request forgery (SSRF)
            if "localhost" in url or "127.0.0.1" in url:
                messagebox.showwarning("Security Alert", "Potential Server-Side Request Forgery (SSRF) Detected!")
            
            # Check for insecure TLS/SSL configurations
            ssl_info = ssl.get_server_certificate((url.split("//")[1].split("/")[0], 443))
            if "TLSv1.1" not in ssl_info or "TLSv1.2" not in ssl_info:
                messagebox.showwarning("Security Alert", "Insecure TLS/SSL Configuration Detected!")
            
            # Display response body
            response_body_text.config(state="normal")
            response_body_text.delete(1.0, tk.END)
            response_body_text.insert(tk.END, response.text)
            response_body_text.config(state="disabled")
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Create the main application window
app = tk.Tk()
app.title("CyberFetch")
app.configure(bg="white")

# Set window size and position
screen_width = app.winfo_screenwidth()
screen_height = app.winfo_screenheight()
app.geometry(f"{int(screen_width * 0.8)}x{int(screen_height * 0.8)}+{int(screen_width * 0.1)}+{int(screen_height * 0.1)}")

# URL entry
url_label = tk.Label(app, text="Enter URL:", fg="navy", bg="white", font=("Arial", 14))
url_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

url_entry = tk.Entry(app, width=50, bg="white", fg="navy", font=("Arial", 14))
url_entry.grid(row=0, column=1, padx=5, pady=5)

# Fetch button
fetch_button = tk.Button(app, text="Fetch URL", command=fetch_url, bg="navy", fg="white", font=("Arial", 14))
fetch_button.grid(row=0, column=2, padx=5, pady=5)

# Status code label
status_code_label = tk.Label(app, text="", fg="navy", bg="white", font=("Arial", 14))
status_code_label.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

# Security headers label
security_headers_label = tk.Label(app, text="", fg="navy", bg="white", font=("Arial", 14))
security_headers_label.grid(row=2, column=0, columnspan=3, padx=5, pady=5)

# Response body text widget
response_body_text = tk.Text(app, width=60, height=20, bg="white", fg="navy", font=("Arial", 12))
response_body_text.grid(row=3, column=0, columnspan=3, padx=5, pady=5)
response_body_text.config(state="disabled")

# Start the Tkinter event loop
app.mainloop()
