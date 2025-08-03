import tkinter as tk
from tkinter import filedialog, messagebox

def start_analysis():
    messagebox.showinfo("Analysis", "Starting Malware Behavioral Analysis...")

def browse_file():
    file_path = filedialog.askopenfilename()
    file_label.config(text=f"Selected: {file_path}")

# GUI Window
root = tk.Tk()
root.title("Malware Behavioral Analysis Tool")
root.geometry("400x200")

# File Selection
file_label = tk.Label(root, text="No file selected")
file_label.pack(pady=10)

browse_button = tk.Button(root, text="Browse File", command=browse_file)
browse_button.pack()

# Start Analysis Button
analyze_button = tk.Button(root, text="Start Analysis", command=start_analysis)
analyze_button.pack(pady=20)

root.mainloop()
