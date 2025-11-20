
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sqlite3
import hashlib
import os
from PIL import Image, ImageTk
import imagehash
import base64
from datetime import datetime

class ImagePasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image-Based Password Security Generator")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        # Initialize database
        self.init_database()

        # Current image path
        self.current_image_path = None
        self.current_image_display = None

        # Setup GUI
        self.setup_gui()

    def init_database(self):
        """Initialize SQLite database with proper schema"""
        try:
            self.conn = sqlite3.connect('password_manager.db')
            self.cursor = self.conn.cursor()

            # Create table for storing password entries
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS password_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    image_hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    password_prefix TEXT NOT NULL,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    UNIQUE(username, service_name)
                )
            """)

            self.conn.commit()
            print("Database initialized successfully")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to initialize database: {e}")

    def setup_gui(self):
        """Setup the main GUI layout"""
        # Create main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights for responsive design
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        # Title
        title_label = ttk.Label(main_frame, text="Image-Based Password Security Generator", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky=tk.W)

        # Left panel for controls
        control_frame = ttk.LabelFrame(main_frame, text="Password Generation", padding="10")
        control_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))

        # Username entry
        ttk.Label(control_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(control_frame, textvariable=self.username_var, width=25)
        username_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Service name entry
        ttk.Label(control_frame, text="Service/Website:").grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        self.service_var = tk.StringVar()
        service_entry = ttk.Entry(control_frame, textvariable=self.service_var, width=25)
        service_entry.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Image upload section
        ttk.Label(control_frame, text="Select Your Unique Image:").grid(row=4, column=0, sticky=tk.W, pady=(0, 5))
        upload_btn = ttk.Button(control_frame, text="Upload Image", command=self.upload_image)
        upload_btn.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Password length selection
        ttk.Label(control_frame, text="Prefix Length:").grid(row=6, column=0, sticky=tk.W, pady=(0, 5))
        self.prefix_length_var = tk.StringVar(value="12")
        length_combo = ttk.Combobox(control_frame, textvariable=self.prefix_length_var, 
                                   values=["8", "12", "16", "20", "24"], state="readonly", width=22)
        length_combo.grid(row=7, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Generate button
        generate_btn = ttk.Button(control_frame, text="Generate Password Prefix", 
                                 command=self.generate_password_prefix)
        generate_btn.grid(row=8, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Result display
        ttk.Label(control_frame, text="Generated Prefix:").grid(row=9, column=0, sticky=tk.W, pady=(0, 5))
        self.result_var = tk.StringVar()
        result_entry = ttk.Entry(control_frame, textvariable=self.result_var, state="readonly", width=25)
        result_entry.grid(row=10, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Copy button
        copy_btn = ttk.Button(control_frame, text="Copy to Clipboard", command=self.copy_to_clipboard)
        copy_btn.grid(row=11, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        # Save button
        save_btn = ttk.Button(control_frame, text="Save Entry", command=self.save_entry)
        save_btn.grid(row=12, column=0, sticky=(tk.W, tk.E))

        # Right panel for image display and saved passwords
        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(1, weight=1)

        # Image display frame
        image_frame = ttk.LabelFrame(right_frame, text="Selected Image", padding="10")
        image_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        image_frame.configure(height=200)

        self.image_label = ttk.Label(image_frame, text="No image selected", 
                                    background="lightgray", anchor="center")
        self.image_label.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        image_frame.columnconfigure(0, weight=1)
        image_frame.rowconfigure(0, weight=1)

        # Saved passwords frame
        saved_frame = ttk.LabelFrame(right_frame, text="Saved Entries", padding="10")
        saved_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Treeview for saved passwords
        columns = ('Username', 'Service', 'Created', 'Last Used')
        self.tree = ttk.Treeview(saved_frame, columns=columns, show='headings', height=10)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)

        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(saved_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # Buttons for saved entries
        button_frame = ttk.Frame(saved_frame)
        button_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        ttk.Button(button_frame, text="Regenerate Selected", 
                  command=self.regenerate_selected).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Delete Selected", 
                  command=self.delete_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh List", 
                  command=self.refresh_saved_list).pack(side=tk.LEFT, padx=5)

        saved_frame.columnconfigure(0, weight=1)
        saved_frame.rowconfigure(0, weight=1)

        # Load saved entries
        self.refresh_saved_list()

    def upload_image(self):
        """Handle image upload"""
        try:
            file_path = filedialog.askopenfilename(
                title="Select an image file",
                filetypes=[
                    ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp *.tiff"),
                    ("All files", "*.*")
                ]
            )

            if file_path:
                # Validate image
                image = Image.open(file_path)
                self.current_image_path = file_path

                # Display image (resized for preview)
                display_image = image.copy()
                display_image.thumbnail((300, 200), Image.Resampling.LANCZOS)

                self.current_image_display = ImageTk.PhotoImage(display_image)
                self.image_label.configure(image=self.current_image_display, text="")

                # Show image info
                width, height = image.size
                file_size = os.path.getsize(file_path) / 1024  # KB
                self.image_label.configure(text=f"Image loaded: {width}x{height} ({file_size:.1f} KB)")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")
            self.current_image_path = None
            self.current_image_display = None
            self.image_label.configure(image="", text="No image selected")

    def generate_password_prefix(self):
        """Generate password prefix from image"""
        if not self.current_image_path:
            messagebox.showwarning("Warning", "Please select an image first")
            return

        if not self.username_var.get().strip():
            messagebox.showwarning("Warning", "Please enter a username")
            return

        if not self.service_var.get().strip():
            messagebox.showwarning("Warning", "Please enter a service name")
            return

        try:
            # Generate salt
            salt = os.urandom(32)

            # Generate image hash using multiple methods for better security
            image = Image.open(self.current_image_path)

            # Get perceptual hash
            perceptual_hash = str(imagehash.phash(image))

            # Get file hash
            with open(self.current_image_path, 'rb') as f:
                file_content = f.read()

            # Combine user data with image data
            combined_data = (
                self.username_var.get() + 
                self.service_var.get() + 
                perceptual_hash + 
                base64.b64encode(file_content[:1024]).decode()  # First 1KB of file
            ).encode('utf-8')

            # Generate hash with salt
            hash_input = salt + combined_data
            password_hash = hashlib.pbkdf2_hmac('sha256', hash_input, salt, 100000)

            # Convert to base64 and take desired length
            prefix_length = int(self.prefix_length_var.get())
            password_prefix = base64.urlsafe_b64encode(password_hash)[:prefix_length].decode('utf-8')

            # Store for potential saving
            self.current_salt = salt
            self.current_image_hash = perceptual_hash
            self.current_password_prefix = password_prefix

            # Display result
            self.result_var.set(password_prefix)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password prefix: {str(e)}")

    def copy_to_clipboard(self):
        """Copy generated prefix to clipboard"""
        if self.result_var.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.result_var.get())
            messagebox.showinfo("Success", "Password prefix copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No password prefix to copy")

    def save_entry(self):
        """Save the current entry to database"""
        if not hasattr(self, 'current_password_prefix'):
            messagebox.showwarning("Warning", "Generate a password prefix first")
            return

        try:
            self.cursor.execute("""
                INSERT OR REPLACE INTO password_entries 
                (username, service_name, image_hash, salt, password_prefix, last_used)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                self.username_var.get(),
                self.service_var.get(),
                self.current_image_hash,
                self.current_salt,
                self.current_password_prefix,
                datetime.now()
            ))

            self.conn.commit()
            messagebox.showinfo("Success", "Entry saved successfully!")
            self.refresh_saved_list()

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to save entry: {str(e)}")

    def refresh_saved_list(self):
        """Refresh the list of saved entries"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            self.cursor.execute("""
                SELECT username, service_name, created_date, last_used 
                FROM password_entries 
                ORDER BY last_used DESC, created_date DESC
            """)

            for row in self.cursor.fetchall():
                # Format dates
                created = datetime.fromisoformat(row[2]).strftime('%Y-%m-%d')
                last_used = datetime.fromisoformat(row[3]).strftime('%Y-%m-%d %H:%M') if row[3] else 'Never'

                self.tree.insert('', 'end', values=(row[0], row[1], created, last_used))

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to load saved entries: {str(e)}")

    def regenerate_selected(self):
        """Regenerate password for selected entry"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an entry to regenerate")
            return

        item = self.tree.item(selection[0])
        username, service_name = item['values'][0], item['values'][1]

        # Load the entry data
        try:
            self.cursor.execute("""
                SELECT image_hash, salt FROM password_entries 
                WHERE username = ? AND service_name = ?
            """, (username, service_name))

            result = self.cursor.fetchone()
            if result:
                # Set the form fields
                self.username_var.set(username)
                self.service_var.set(service_name)

                # Generate new prefix using stored data
                image_hash, salt = result
                combined_data = (username + service_name + image_hash).encode('utf-8')
                hash_input = salt + combined_data
                password_hash = hashlib.pbkdf2_hmac('sha256', hash_input, salt, 100000)

                prefix_length = int(self.prefix_length_var.get())
                password_prefix = base64.urlsafe_b64encode(password_hash)[:prefix_length].decode('utf-8')

                self.result_var.set(password_prefix)

                # Update last used time
                self.current_salt = salt
                self.current_image_hash = image_hash
                self.current_password_prefix = password_prefix

                self.cursor.execute("""
                    UPDATE password_entries SET last_used = ? 
                    WHERE username = ? AND service_name = ?
                """, (datetime.now(), username, service_name))
                self.conn.commit()

                self.refresh_saved_list()
                messagebox.showinfo("Success", "Password prefix regenerated!")

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to regenerate: {str(e)}")

    def delete_selected(self):
        """Delete selected entry"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an entry to delete")
            return

        item = self.tree.item(selection[0])
        username, service_name = item['values'][0], item['values'][1]

        if messagebox.askyesno("Confirm Delete", 
                              f"Delete entry for {username} - {service_name}?"):
            try:
                self.cursor.execute("""
                    DELETE FROM password_entries 
                    WHERE username = ? AND service_name = ?
                """, (username, service_name))

                self.conn.commit()
                self.refresh_saved_list()
                messagebox.showinfo("Success", "Entry deleted successfully!")

            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"Failed to delete entry: {str(e)}")

    def __del__(self):
        """Cleanup database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()

def main():
    """Main function to run the application"""
    root = tk.Tk()

    # Set modern theme if available
    try:
        style = ttk.Style()
        style.theme_use('clam')  # Modern theme
    except:
        pass  # Use default theme if clam is not available

    app = ImagePasswordApp(root)

    # Handle window closing
    def on_closing():
        if hasattr(app, 'conn'):
            app.conn.close()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()
