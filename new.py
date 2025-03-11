import customtkinter as ctk
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from gpt4all import GPT4All
import os
import threading
import asyncio
import json
import hashlib

# Initialize customtkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# File to store user credentials
USER_FILE = "users.json"
model = None  # Initialize as None, load later after login


# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Function to save user credentials
def save_user(username, password):
    users = load_users()
    users[username] = hash_password(password)
    with open(USER_FILE, "w") as f:
        json.dump(users, f)


# Function to load user credentials
def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            return json.load(f)
    return {}


# Function to check login
def check_login():
    global model
    username = username_entry.get().strip()
    password = password_entry.get().strip()
    users = load_users()

    if username in users and users[username] == hash_password(password):
        messagebox.showinfo("Login Successful", f"Welcome {username}!")

        # Ask for model file
        model_path = filedialog.askopenfilename(title="Select GPT4All Model File", filetypes=[("GGUF Model", "*.gguf")])
        if not model_path or not os.path.exists(model_path):
            messagebox.showerror("Error", "No model file selected. Exiting...")
            return

        print(f"Using model: {model_path}")
        model = GPT4All(model_path, allow_download=False)

        login_frame.pack_forget()
        intro_frame.pack(fill="both", expand=True)
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")


# Function to register a new user
def register():
    new_username = username_entry.get().strip()
    new_password = password_entry.get().strip()

    if not new_username or not new_password:
        messagebox.showerror("Error", "Username and password cannot be empty.")
        return

    users = load_users()

    if new_username in users:
        messagebox.showerror("Error", "Username already exists! Choose a different one.")
        return

    save_user(new_username, new_password)
    messagebox.showinfo("Success", "Account created! You can now log in.")
    show_login()


# Function to show login page
def show_login():
    register_frame.pack_forget()
    intro_frame.pack_forget()
    chatbot_frame.pack_forget()
    login_frame.pack(fill="both", expand=True)


# Function to show registration page
def show_register():
    login_frame.pack_forget()
    register_frame.pack(fill="both", expand=True)


# Function to sign out and go back to login page
def sign_out():
    messagebox.showinfo("Logged Out", "You have been signed out.")
    intro_frame.pack_forget()
    login_frame.pack(fill="both", expand=True)


# Create main window
root = ctk.CTk()
root.title("Falcon - AI Chatbot")
root.geometry("1000x700")  # Enlarged window size

# Login Frame
login_frame = ctk.CTkFrame(root)
login_frame.pack(fill="both", expand=True)

ctk.CTkLabel(login_frame, text="Login to Falcon AI", font=("Arial", 24, "bold")).pack(pady=20)
username_entry = ctk.CTkEntry(login_frame, placeholder_text="Username")
username_entry.pack(pady=10)
password_entry = ctk.CTkEntry(login_frame, placeholder_text="Password", show="*")
password_entry.pack(pady=10)
ctk.CTkButton(login_frame, text="Login", command=check_login).pack(pady=10)
ctk.CTkButton(login_frame, text="Create an Account", command=show_register).pack(pady=10)

# Registration Frame
register_frame = ctk.CTkFrame(root)

ctk.CTkLabel(register_frame, text="Create a Falcon AI Account", font=("Arial", 24, "bold")).pack(pady=20)
username_entry = ctk.CTkEntry(register_frame, placeholder_text="New Username")
username_entry.pack(pady=10)
password_entry = ctk.CTkEntry(register_frame, placeholder_text="New Password", show="*")
password_entry.pack(pady=10)
ctk.CTkButton(register_frame, text="Sign Up", command=register).pack(pady=10)
ctk.CTkButton(register_frame, text="Back to Login", command=show_login).pack(pady=10)

# Introduction Frame (Hidden Initially)
intro_frame = ctk.CTkFrame(root)

def open_chatbot():
    intro_frame.pack_forget()
    chatbot_frame.pack(fill="both", expand=True)

def go_back():
    chatbot_frame.pack_forget()
    intro_frame.pack(fill="both", expand=True)  # FIXED: Now properly switches back

ctk.CTkLabel(intro_frame, text="Welcome to Falcon AI", font=("Arial", 28, "bold")).pack(pady=20)
ctk.CTkButton(intro_frame, text="Enter Falcon Environment", command=open_chatbot).pack(pady=20)
sign_out_button = ctk.CTkButton(intro_frame, text="Sign Out", command=sign_out, fg_color="red")
sign_out_button.pack(pady=10)

# Chatbot Frame
chatbot_frame = ctk.CTkFrame(root)

back_button = ctk.CTkButton(chatbot_frame, text="← Back", command=go_back)
back_button.pack(anchor="nw", padx=10, pady=10)

# Stylish Search Bar
search_frame = ctk.CTkFrame(chatbot_frame, corner_radius=20)
search_frame.pack(pady=10, padx=10, fill="x")

search_entry = ctk.CTkEntry(search_frame, placeholder_text="Ask something...", height=40, width=700, corner_radius=20, font=("Arial", 14))
search_entry.pack(side="left", padx=10, pady=5, expand=True)

search_icon = ctk.CTkButton(search_frame, text="🔍", width=40, height=40, fg_color="transparent", hover_color="#555", command=lambda: get_response())
search_icon.pack(side="right", padx=10, pady=5)

search_entry.bind("<Return>", lambda event: get_response())

# Chat Output Area
output_text = scrolledtext.ScrolledText(chatbot_frame, width=100, height=30, font=("Arial", 12), wrap=tk.WORD)
output_text.pack(pady=10)
output_text.configure(state=tk.DISABLED)

# Get Response Function
def get_response():
    if model is None:
        messagebox.showerror("Error", "AI Model is not loaded. Please restart and log in again.")
        return

    user_input = search_entry.get().strip()
    if not user_input:
        messagebox.showwarning("Warning", "Please enter a question!")
        return

    output_text.configure(state=tk.NORMAL)
    output_text.insert(tk.END, "\n🧑‍💻 You: " + user_input + "\n", "user")
    output_text.configure(state=tk.DISABLED)
    search_entry.delete(0, tk.END)

    def fetch_response():
        response = model.generate(user_input)
        asyncio.run(type_response(response))

    threading.Thread(target=fetch_response).start()

async def type_response(response):
    output_text.configure(state=tk.NORMAL)
    output_text.insert(tk.END, "🤖 Falcon: ", "ai")
    for char in response:
        output_text.insert(tk.END, char, "ai")
        output_text.update()
        await asyncio.sleep(0.02)
    output_text.insert(tk.END, "\n")
    output_text.configure(state=tk.DISABLED)

root.mainloop()
