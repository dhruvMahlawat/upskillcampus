

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import hashlib
import secrets
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json
from datetime import datetime


class PasswordManager:
    def __init__(self):
        self.db_path = "passwords.db"
        self.config_path = "config.json"
        self.master_key = None
        self.cipher_suite = None
        self.setup_database()

    def setup_database(self):
        """Initialize the database with required tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                created_date TEXT NOT NULL,
                modified_date TEXT NOT NULL
            )
        ''')

        # Create master password table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')

        conn.commit()
        conn.close()

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def set_master_password(self, password: str) -> bool:
        """Set the master password for the first time."""
        try:
            salt = os.urandom(16)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO master_password (id, salt, password_hash) VALUES (1, ?, ?)",
                (base64.b64encode(salt).decode(), base64.b64encode(password_hash).decode())
            )
            conn.commit()
            conn.close()

            # Initialize encryption
            self.master_key = self.derive_key(password, salt)
            self.cipher_suite = Fernet(self.master_key)
            return True
        except Exception as e:
            print(f"Error setting master password: {e}")
            return False

    def verify_master_password(self, password: str) -> bool:
        """Verify the master password."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT salt, password_hash FROM master_password WHERE id = 1")
            result = cursor.fetchone()
            conn.close()

            if not result:
                return False

            salt = base64.b64decode(result[0])
            stored_hash = base64.b64decode(result[1])

            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

            if password_hash == stored_hash:
                self.master_key = self.derive_key(password, salt)
                self.cipher_suite = Fernet(self.master_key)
                return True
            return False
        except Exception as e:
            print(f"Error verifying master password: {e}")
            return False

    def has_master_password(self) -> bool:
        """Check if master password is already set."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM master_password WHERE id = 1")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def generate_password(self, length: int = 12, include_symbols: bool = True) -> str:
        """Generate a strong random password."""
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password

    def encrypt_password(self, password: str) -> str:
        """Encrypt a password using the master key."""
        if not self.cipher_suite:
            raise ValueError("Master password not set")

        encrypted = self.cipher_suite.encrypt(password.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt a password using the master key."""
        if not self.cipher_suite:
            raise ValueError("Master password not set")

        encrypted_bytes = base64.b64decode(encrypted_password.encode())
        decrypted = self.cipher_suite.decrypt(encrypted_bytes)
        return decrypted.decode()

    def add_password(self, website: str, username: str, password: str) -> bool:
        """Add a new password entry to the database."""
        try:
            encrypted_password = self.encrypt_password(password)
            now = datetime.now().isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO passwords (website, username, encrypted_password, created_date, modified_date) VALUES (?, ?, ?, ?, ?)",
                (website, username, encrypted_password, now, now)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error adding password: {e}")
            return False

    def get_passwords(self) -> list:
        """Retrieve all password entries."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, website, username, encrypted_password, created_date, modified_date FROM passwords")
        results = cursor.fetchall()
        conn.close()

        passwords = []
        for row in results:
            try:
                decrypted_password = self.decrypt_password(row[3])
                passwords.append({
                    'id': row[0],
                    'website': row[1],
                    'username': row[2],
                    'password': decrypted_password,
                    'created_date': row[4],
                    'modified_date': row[5]
                })
            except Exception as e:
                print(f"Error decrypting password for {row[1]}: {e}")
                continue

        return passwords

    def search_passwords(self, query: str) -> list:
        """Search for passwords by website or username."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, website, username, encrypted_password, created_date, modified_date FROM passwords WHERE website LIKE ? OR username LIKE ?",
            (f"%{query}%", f"%{query}%")
        )
        results = cursor.fetchall()
        conn.close()

        passwords = []
        for row in results:
            try:
                decrypted_password = self.decrypt_password(row[3])
                passwords.append({
                    'id': row[0],
                    'website': row[1],
                    'username': row[2],
                    'password': decrypted_password,
                    'created_date': row[4],
                    'modified_date': row[5]
                })
            except Exception as e:
                print(f"Error decrypting password for {row[1]}: {e}")
                continue

        return passwords

    def update_password(self, password_id: int, website: str, username: str, password: str) -> bool:
        """Update an existing password entry."""
        try:
            encrypted_password = self.encrypt_password(password)
            now = datetime.now().isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE passwords SET website = ?, username = ?, encrypted_password = ?, modified_date = ? WHERE id = ?",
                (website, username, encrypted_password, now, password_id)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error updating password: {e}")
            return False

    def delete_password(self, password_id: int) -> bool:
        """Delete a password entry."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error deleting password: {e}")
            return False


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')

        self.pm = PasswordManager()
        self.current_passwords = []

        self.setup_styles()
        self.authenticate_user()

    def setup_styles(self):
        """Configure the GUI styles."""
        style = ttk.Style()
        style.theme_use('clam')

        # Configure custom styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#f0f0f0')
        style.configure('Heading.TLabel', font=('Arial', 12, 'bold'), background='#f0f0f0')
        style.configure('Action.TButton', font=('Arial', 10, 'bold'))

    def authenticate_user(self):
        """Handle user authentication."""
        if not self.pm.has_master_password():
            self.setup_master_password()
        else:
            self.login()

    def setup_master_password(self):
        """Set up the master password for first-time users."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Setup Master Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        ttk.Label(dialog, text="Welcome to Password Manager!", style='Title.TLabel').pack(pady=20)
        ttk.Label(dialog, text="Please set your master password:", style='Heading.TLabel').pack(pady=10)

        ttk.Label(dialog, text="Master Password:").pack(pady=5)
        password_entry = ttk.Entry(dialog, show="*", width=30)
        password_entry.pack(pady=5)

        ttk.Label(dialog, text="Confirm Password:").pack(pady=5)
        confirm_entry = ttk.Entry(dialog, show="*", width=30)
        confirm_entry.pack(pady=5)

        def set_password():
            password = password_entry.get()
            confirm = confirm_entry.get()

            if len(password) < 8:
                messagebox.showerror("Error", "Master password must be at least 8 characters long!")
                return

            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match!")
                return

            if self.pm.set_master_password(password):
                messagebox.showinfo("Success", "Master password set successfully!")
                dialog.destroy()
                self.create_main_interface()
            else:
                messagebox.showerror("Error", "Failed to set master password!")

        ttk.Button(dialog, text="Set Password", command=set_password, style='Action.TButton').pack(pady=20)

        password_entry.focus()
        dialog.bind('<Return>', lambda e: set_password())

    def login(self):
        """Handle user login."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Login")
        dialog.geometry("350x200")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        ttk.Label(dialog, text="Password Manager", style='Title.TLabel').pack(pady=20)
        ttk.Label(dialog, text="Enter your master password:", style='Heading.TLabel').pack(pady=10)

        password_entry = ttk.Entry(dialog, show="*", width=30)
        password_entry.pack(pady=10)

        def verify_password():
            password = password_entry.get()
            if self.pm.verify_master_password(password):
                dialog.destroy()
                self.create_main_interface()
            else:
                messagebox.showerror("Error", "Invalid master password!")
                password_entry.delete(0, tk.END)

        ttk.Button(dialog, text="Login", command=verify_password, style='Action.TButton').pack(pady=10)

        password_entry.focus()
        dialog.bind('<Return>', lambda e: verify_password())

    def create_main_interface(self):
        """Create the main application interface."""
        # Clear the root window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        ttk.Label(main_frame, text="Password Manager", style='Title.TLabel').pack(pady=(0, 20))

        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Button(button_frame, text="Add Password", command=self.add_password_dialog, style='Action.TButton').pack(
            side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate Password", command=self.generate_password_dialog,
                   style='Action.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh", command=self.refresh_passwords, style='Action.TButton').pack(
            side=tk.LEFT, padx=5)

        # Search frame
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(search_frame, text="Search", command=self.search_passwords).pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Clear", command=self.clear_search).pack(side=tk.LEFT, padx=5)

        # Password list frame
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview for password list
        columns = ('Website', 'Username', 'Created', 'Modified')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)

        # Define headings
        self.tree.heading('Website', text='Website')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Created', text='Created')
        self.tree.heading('Modified', text='Modified')

        # Configure column widths
        self.tree.column('Website', width=200)
        self.tree.column('Username', width=150)
        self.tree.column('Created', width=150)
        self.tree.column('Modified', width=150)

        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Pack treeview and scrollbar
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="View Password", command=self.view_password)
        self.context_menu.add_command(label="Copy Password", command=self.copy_password)
        self.context_menu.add_command(label="Edit", command=self.edit_password)
        self.context_menu.add_command(label="Delete", command=self.delete_password)

        # Bind right-click to show context menu
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.view_password)

        # Load passwords
        self.refresh_passwords()

    def show_context_menu(self, event):
        """Show context menu on right-click."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def refresh_passwords(self):
        """Refresh the password list."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Load passwords
        self.current_passwords = self.pm.get_passwords()

        # Populate treeview
        for password in self.current_passwords:
            created = password['created_date'][:10] if password['created_date'] else 'Unknown'
            modified = password['modified_date'][:10] if password['modified_date'] else 'Unknown'

            self.tree.insert('', tk.END, values=(
                password['website'],
                password['username'],
                created,
                modified
            ))

    def search_passwords(self):
        """Search for passwords."""
        query = self.search_var.get().strip()
        if not query:
            self.refresh_passwords()
            return

        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Search passwords
        results = self.pm.search_passwords(query)

        # Populate treeview with results
        for password in results:
            created = password['created_date'][:10] if password['created_date'] else 'Unknown'
            modified = password['modified_date'][:10] if password['modified_date'] else 'Unknown'

            self.tree.insert('', tk.END, values=(
                password['website'],
                password['username'],
                created,
                modified
            ))

        # Update current passwords for context menu actions
        self.current_passwords = results

    def clear_search(self):
        """Clear search and refresh all passwords."""
        self.search_var.set('')
        self.refresh_passwords()

    def add_password_dialog(self):
        """Show dialog to add a new password."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        ttk.Label(dialog, text="Add New Password", style='Title.TLabel').pack(pady=10)

        # Website
        ttk.Label(dialog, text="Website:").pack(pady=5)
        website_entry = ttk.Entry(dialog, width=40)
        website_entry.pack(pady=5)

        # Username
        ttk.Label(dialog, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(dialog, width=40)
        username_entry.pack(pady=5)

        # Password
        ttk.Label(dialog, text="Password:").pack(pady=5)
        password_frame = ttk.Frame(dialog)
        password_frame.pack(pady=5)

        password_entry = ttk.Entry(password_frame, show="*", width=30)
        password_entry.pack(side=tk.LEFT, padx=(0, 5))

        def generate_password():
            generated = self.pm.generate_password()
            password_entry.delete(0, tk.END)
            password_entry.insert(0, generated)

        ttk.Button(password_frame, text="Generate", command=generate_password).pack(side=tk.LEFT)

        def save_password():
            website = website_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()

            if not website or not username or not password:
                messagebox.showerror("Error", "All fields are required!")
                return

            if self.pm.add_password(website, username, password):
                messagebox.showinfo("Success", "Password added successfully!")
                dialog.destroy()
                self.refresh_passwords()
            else:
                messagebox.showerror("Error", "Failed to add password!")

        ttk.Button(dialog, text="Save", command=save_password, style='Action.TButton').pack(pady=20)

        website_entry.focus()

    def generate_password_dialog(self):
        """Show dialog to generate a password."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        ttk.Label(dialog, text="Password Generator", style='Title.TLabel').pack(pady=10)

        # Length
        ttk.Label(dialog, text="Password Length:").pack(pady=5)
        length_var = tk.IntVar(value=12)
        length_spinbox = ttk.Spinbox(dialog, from_=8, to=64, textvariable=length_var, width=10)
        length_spinbox.pack(pady=5)

        # Include symbols
        include_symbols = tk.BooleanVar(value=True)
        ttk.Checkbutton(dialog, text="Include Symbols", variable=include_symbols).pack(pady=5)

        # Generated password display
        ttk.Label(dialog, text="Generated Password:").pack(pady=(20, 5))
        password_var = tk.StringVar()
        password_entry = ttk.Entry(dialog, textvariable=password_var, width=40, state='readonly')
        password_entry.pack(pady=5)

        def generate():
            length = length_var.get()
            symbols = include_symbols.get()
            generated = self.pm.generate_password(length, symbols)
            password_var.set(generated)

        def copy_to_clipboard():
            password = password_var.get()
            if password:
                self.root.clipboard_clear()
                self.root.clipboard_append(password)
                messagebox.showinfo("Success", "Password copied to clipboard!")

        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Generate", command=generate, style='Action.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy", command=copy_to_clipboard, style='Action.TButton').pack(side=tk.LEFT,
                                                                                                      padx=5)

        # Generate initial password
        generate()

    def get_selected_password(self):
        """Get the currently selected password."""
        selection = self.tree.selection()
        if not selection:
            return None

        item = self.tree.item(selection[0])
        website = item['values'][0]
        username = item['values'][1]

        # Find the password in current_passwords
        for password in self.current_passwords:
            if password['website'] == website and password['username'] == username:
                return password
        return None

    def view_password(self):
        """View the selected password."""
        password_data = self.get_selected_password()
        if not password_data:
            messagebox.showwarning("Warning", "Please select a password to view!")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("View Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        ttk.Label(dialog, text="Password Details", style='Title.TLabel').pack(pady=10)

        # Details frame
        details_frame = ttk.Frame(dialog)
        details_frame.pack(pady=20, padx=20, fill=tk.BOTH)

        ttk.Label(details_frame, text="Website:", style='Heading.TLabel').grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Label(details_frame, text=password_data['website']).grid(row=0, column=1, sticky=tk.W, pady=5, padx=(10, 0))

        ttk.Label(details_frame, text="Username:", style='Heading.TLabel').grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Label(details_frame, text=password_data['username']).grid(row=1, column=1, sticky=tk.W, pady=5,
                                                                      padx=(10, 0))

        ttk.Label(details_frame, text="Password:", style='Heading.TLabel').grid(row=2, column=0, sticky=tk.W, pady=5)

        password_frame = ttk.Frame(details_frame)
        password_frame.grid(row=2, column=1, sticky=tk.W, pady=5, padx=(10, 0))

        show_password = tk.BooleanVar()
        password_var = tk.StringVar(value="*" * len(password_data['password']))
        password_label = ttk.Label(password_frame, textvariable=password_var, font=('Courier', 10))
        password_label.pack(side=tk.LEFT)

        def toggle_password():
            if show_password.get():
                password_var.set(password_data['password'])
            else:
                password_var.set("*" * len(password_data['password']))

        ttk.Checkbutton(password_frame, text="Show", variable=show_password, command=toggle_password).pack(side=tk.LEFT,
                                                                                                           padx=(10, 0))

        ttk.Label(details_frame, text="Created:", style='Heading.TLabel').grid(row=3, column=0, sticky=tk.W, pady=5)
        created_date = password_data['created_date'][:19] if password_data['created_date'] else 'Unknown'
        ttk.Label(details_frame, text=created_date).grid(row=3, column=1, sticky=tk.W, pady=5, padx=(10, 0))

        ttk.Label(details_frame, text="Modified:", style='Heading.TLabel').grid(row=4, column=0, sticky=tk.W, pady=5)
        modified_date = password_data['modified_date'][:19] if password_data['modified_date'] else 'Unknown'
        ttk.Label(details_frame, text=modified_date).grid(row=4, column=1, sticky=tk.W, pady=5, padx=(10, 0))

        def copy_password():
            self.root.clipboard_clear()
            self.root.clipboard_append(password_data['password'])
            messagebox.showinfo("Success", "Password copied to clipboard!")

        ttk.Button(dialog, text="Copy Password", command=copy_password, style='Action.TButton').pack(pady=20)

    def copy_password(self):
        """Copy the selected password to clipboard."""
        password_data = self.get_selected_password()
        if not password_data:
            messagebox.showwarning("Warning", "Please select a password to copy!")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(password_data['password'])
        messagebox.showinfo("Success", "Password copied to clipboard!")

    def edit_password(self):
        """Edit the selected password."""
        password_data = self.get_selected_password()
        if not password_data:
            messagebox.showwarning("Warning", "Please select a password to edit!")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Password")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")

        ttk.Label(dialog, text="Edit Password", style='Title.TLabel').pack(pady=10)

        # Website
        ttk.Label(dialog, text="Website:").pack(pady=5)
        website_entry = ttk.Entry(dialog, width=40)
        website_entry.pack(pady=5)
        website_entry.insert(0, password_data['website'])

        # Username
        ttk.Label(dialog, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(dialog, width=40)
        username_entry.pack(pady=5)
        username_entry.insert(0, password_data['username'])

        # Password
        ttk.Label(dialog, text="Password:").pack(pady=5)
        password_frame = ttk.Frame(dialog)
        password_frame.pack(pady=5)

        password_entry = ttk.Entry(password_frame, show="*", width=30)
        password_entry.pack(side=tk.LEFT, padx=(0, 5))
        password_entry.insert(0, password_data['password'])

        def generate_password():
            generated = self.pm.generate_password()
            password_entry.delete(0, tk.END)
            password_entry.insert(0, generated)

        ttk.Button(password_frame, text="Generate", command=generate_password).pack(side=tk.LEFT)

        def update_password():
            website = website_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()

            if not website or not username or not password:
                messagebox.showerror("Error", "All fields are required!")
                return

            if self.pm.update_password(password_data['id'], website, username, password):
                messagebox.showinfo("Success", "Password updated successfully!")
                dialog.destroy()
                self.refresh_passwords()
            else:
                messagebox.showerror("Error", "Failed to update password!")

        ttk.Button(dialog, text="Update", command=update_password, style='Action.TButton').pack(pady=20)

        website_entry.focus()

    def delete_password(self):
        """Delete the selected password."""
        password_data = self.get_selected_password()
        if not password_data:
            messagebox.showwarning("Warning", "Please select a password to delete!")
            return

        result = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete the password for {password_data['website']}?"
        )

        if result:
            if self.pm.delete_password(password_data['id']):
                messagebox.showinfo("Success", "Password deleted successfully!")
                self.refresh_passwords()
            else:
                messagebox.showerror("Error", "Failed to delete password!")


def main():
    """Main function to run the password manager."""
    try:
        root = tk.Tk()
        app = PasswordManagerGUI(root)
        root.mainloop()
    except ImportError as e:
        print(f"Missing required library: {e}")
        print("Please install required dependencies:")
        print("pip install cryptography")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()