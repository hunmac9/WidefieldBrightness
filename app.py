import sys
import os
import cv2
import numpy as np
import logging
import csv
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from multiprocessing import Manager
from tkinter import Tk, filedialog, messagebox, Text, Scrollbar, END
from tkinter import ttk
from threading import Thread

class GUIHandler(logging.Handler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record) + '\n'
        self.text_widget.insert(END, msg)
        self.text_widget.see(END)

def configure_logger(text_widget):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    if not logger.handlers:
        handler = GUIHandler(text_widget)
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

def parse_datetime_from_filename(filename):
    try:
        basename = os.path.basename(filename)
        name_part = basename.split('.')[0]
        datetime_str = '_'.join(name_part.split('_')[-2:])
        return datetime.strptime(datetime_str, '%Y-%m-%d_%H-%M-%S')
    except ValueError:
        logging.warning(f"Filename {filename} does not match the expected format, using file modification time")
        return None

def get_file_modification_time(filepath):
    timestamp = os.path.getmtime(filepath)
    return datetime.fromtimestamp(timestamp)

def calculate_brightness(image_path):
    try:
        img = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
        if img is None:
            raise ValueError(f"Image {image_path} could not be read")
        avg_brightness = np.mean(img)
        return avg_brightness
    except Exception as e:
        logging.warning(f"Could not process image {image_path}: {e}")
        return None

def process_image(image_path, processed_images):
    if image_path in processed_images:
        logging.info(f"Image {image_path} already processed, skipping")
        return None

    logging.info(f"Started processing image: {image_path}")
    brightness = calculate_brightness(image_path)
    if brightness is not None:
        processed_images.append(image_path)
        datetime_taken = parse_datetime_from_filename(image_path)
        if datetime_taken is None:
            datetime_taken = get_file_modification_time(image_path)

        logging.info(f"brightness of image {image_path}: {brightness:.2f}, Taken at: {datetime_taken}")
        return brightness, datetime_taken
    return None

def process_images(directory_path, output_filepath, progress_bar, log_text, total_images):
    images = [file.path for file in os.scandir(directory_path) if file.name.endswith(".tiff") and not file.name.startswith("._")]

    with Manager() as manager:
        processed_images = manager.list()
        all_results = []

        num_workers = min(4, os.cpu_count() or 1)
        processed_count = 0

        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = {executor.submit(process_image, image, processed_images): image for image in images}

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        brightness, datetime_taken = result
                        all_results.append((brightness, datetime_taken))
                        log_text.insert(END, f"Determined brightness of {brightness} for image taken at {datetime_taken}\n")
                        log_text.see(END)
                except Exception as exc:
                    log_text.insert(END, f"Image processing generated an exception: {exc}\n")
                    log_text.see(END)
                finally:
                    processed_count += 1
                    progress_bar['value'] = (processed_count / total_images) * 100
                    progress_bar.update_idletasks()

        if all_results:
            with open(output_filepath, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['brightness', 'Timestamp'])
                for row in all_results:
                    writer.writerow(row)

            return output_filepath
        else:
            return None

def select_directory():
    directory_path = filedialog.askdirectory(title="Select Directory with Images")
    if directory_path:
        input_dir_entry.delete(0, END)
        input_dir_entry.insert(0, directory_path)

def select_output_file():
    output_filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Select Output CSV File")
    if output_filepath:
        output_file_entry.delete(0, END)
        output_file_entry.insert(0, output_filepath)

def start_processing():
    directory_path = input_dir_entry.get()
    output_filepath = output_file_entry.get()

    if not directory_path or not os.path.isdir(directory_path):
        messagebox.showerror("Error", "Please select a valid directory.")
        return

    if not output_filepath:
        messagebox.showerror("Error", "Please select a valid output file.")
        return

    configure_logger(log_text)

    images = [file.path for file in os.scandir(directory_path) if file.name.endswith(".tiff") and not file.name.startswith("._")]
    total_images = len(images)
    if total_images == 0:
        messagebox.showerror("Error", "No images found in the directory.")
        return
    progress_bar['maximum'] = 100 
    progress_bar['value'] = 0

    logging.info(f"Starting processing for directory: {directory_path}")
    logging.info(f"Output will be saved to: {output_filepath}")

    def threaded_processing():
        try:
            result = process_images(directory_path, output_filepath, progress_bar, log_text, total_images)
            if result:
                messagebox.showinfo("Success", f"brightness data saved to {output_filepath}")
            else:
                messagebox.showwarning("Warning", "No brightness data was processed.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
            messagebox.showerror("Error", f"An error occurred: {e}")

    Thread(target=threaded_processing).start()

if __name__ == "__main__":
    root = Tk()
    root.title("Brightness Extractor")

    ttk.Label(root, text="Input Directory:").grid(row=0, column=0, padx=10, pady=10)
    input_dir_entry = ttk.Entry(root, width=50)
    input_dir_entry.grid(row=0, column=1, padx=10, pady=10)
    input_dir_button = ttk.Button(root, text="Browse...", command=select_directory)
    input_dir_button.grid(row=0, column=2, padx=10, pady=10)

    ttk.Label(root, text="Output File:").grid(row=1, column=0, padx=10, pady=10)
    output_file_entry = ttk.Entry(root, width=50)
    output_file_entry.grid(row=1, column=1, padx=10, pady=10)
    output_file_button = ttk.Button(root, text="Browse...", command=select_output_file)
    output_file_button.grid(row=1, column=2, padx=10, pady=10)

    process_button = ttk.Button(root, text="Start Processing", command=start_processing)
    process_button.grid(row=2, column=1, padx=10, pady=10)

    progress_bar = ttk.Progressbar(root, orient="horizontal", mode="determinate", maximum=100, value=0)
    progress_bar.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="we")

    log_frame = ttk.LabelFrame(root, text="Log")
    log_frame.grid(row=4, column=0, columnspan=3, padx=10, pady=10, sticky="nswe")
    log_frame.grid_columnconfigure(0, weight=1)
    log_frame.grid_rowconfigure(0, weight=1)

    log_text = Text(log_frame, state="normal", height=10, wrap="word")
    log_text.grid(row=0, column=0, sticky="nswe")
    scrollbar = Scrollbar(log_frame, orient="vertical", command=log_text.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    log_text.config(yscrollcommand=scrollbar.set)

    root.mainloop()
