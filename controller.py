from cryptography.fernet import Fernet
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from tkinter import messagebox
import tkinter as tk
from sql_database import SessionLocal, User
from datetime import datetime
from sql_database import Message


with open("Encryption_key.txt", "rb") as l:
    key = l.read().strip()
cipher = Fernet(key)
del key
def decrypt_txt(txt):
    return cipher.decrypt(txt.encode()).decode()
class UserManagerApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="cyborg")
        self.title("AI Control Switch")
        self.geometry("500x500")
        self.entry = None
        self.user_vars = []

        # Scrollable container setup
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True, padx=10, pady=10)

        canvas = ttk.Canvas(container)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.scroll_frame = ttk.Frame(canvas)

        self.scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.load_users()

    def clear_users(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
        self.user_vars.clear()

    def refresh_users(self):
        self.clear_users()
        self.load_users()

    def search_(self):
        search_text = self.entry.get().strip().lower()
        self.clear_users()
        self.load_header_and_search_bar()

        session = SessionLocal()
        users = session.query(User).filter(User.remove_from_display == False).all()
        for user in users:
            if (search_text in decrypt_txt(user.first_name).lower()) or (
                    search_text in decrypt_txt(user.last_name).lower()):
                self.add_user_row(user.id, decrypt_txt(user.first_name), decrypt_txt(user.last_name), user.approved)
        session.close()

    def search__(self, event):
        self.search_()

    def load_users(self):
        self.load_header_and_search_bar()

        session = SessionLocal()
        users = session.query(User).filter(User.remove_from_display == False).order_by(User.created_at.desc()).all()
        session.close()

        for user in users:
            self.add_user_row(user.id, decrypt_txt(user.first_name), decrypt_txt(user.last_name), user.approved)
    def delete(self):
        pw_window = tk.Toplevel(self)
        pw_window.title("Enter Password")
        pw_window.geometry("300x150")
        pw_window.resizable(False, False)

        # Center the Toplevel over the main window
        pw_window.transient(self)
        pw_window.grab_set()  # Make modal

        # Password label and entry
        lbl = ttk.Label(pw_window, text="Password:")
        lbl.pack(pady=(20, 5))

        password_var = tk.StringVar()
        pw_entry = ttk.Entry(pw_window, textvariable=password_var, show="*")
        pw_entry.pack(pady=5)
        pw_entry.focus()

        # Button frame
        btn_frame = ttk.Frame(pw_window)
        btn_frame.pack(pady=10)

        def submit_password():
            password = password_var.get()
            if password:
                if password == "gametime121a4fb7c9a":
                    self.deletion_window()
                else:
                    Messagebox.show_warning("Wrong password.", title="Input Error")

            else:
                Messagebox.show_warning("Please enter a password.", title="Input Error")

        def cancel():
            pw_window.destroy()

        ok_btn = ttk.Button(btn_frame, text="OK", command=submit_password, bootstyle=PRIMARY)
        ok_btn.pack(side=LEFT, padx=5)

        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=cancel, bootstyle=SECONDARY)
        cancel_btn.pack(side=LEFT, padx=5)

    def deletion_window(self):
        delete_win = tk.Toplevel(self)
        delete_win.title("Select Users to Delete")
        delete_win.geometry("400x400")
        delete_win.transient(self)
        delete_win.grab_set()

        ttk.Label(delete_win, text="Select users to delete:", font=("Helvetica", 12)).pack(pady=10)

        delete_frame = ttk.Frame(delete_win)
        delete_frame.pack(fill="both", expand=True, padx=10, pady=10)

        canvas = ttk.Canvas(delete_frame)
        scroll = ttk.Scrollbar(delete_frame, orient="vertical", command=canvas.yview)
        inner_frame = ttk.Frame(canvas)

        inner_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=inner_frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)

        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # Checkbox logic
        check_vars = []
        session = SessionLocal()
        users = session.query(User).filter(User.remove_from_display == False).all()
        session.close()

        for user in users:
            full_name = f"{decrypt_txt(user.first_name)} {decrypt_txt(user.last_name)}"
            var = tk.BooleanVar()
            ttk.Checkbutton(inner_frame, text=full_name, variable=var).pack(anchor="w")
            check_vars.append((user.id, var))

        def confirm_deletion():
            selected_ids = [uid for uid, var in check_vars if var.get()]
            if not selected_ids:
                Messagebox.show_info("No users selected.", title="Info")
                return

            confirmed = messagebox.askyesno("Confirm", f"Delete {len(selected_ids)} user(s)?")
            if confirmed:
                session = SessionLocal()
                for uid in selected_ids:
                    user = session.query(User).get(uid)
                    if user:
                        user.remove_from_display = True
                session.commit()
                session.close()

                Messagebox.show_info("Selected users marked for deletion.")
                delete_win.destroy()
                self.refresh_users()

        ttk.Button(delete_win, text="Delete Selected", bootstyle="danger", command=confirm_deletion).pack(pady=10)

    def update_user_status(self, sender_id, is_allowed):
        session = SessionLocal()
        user = session.query(User).filter_by(id=sender_id).first()
        if user:
            user.approved = "yes" if is_allowed else "no"
            session.commit()
        session.close()

    def above12(self):
        self.clear_users()
        self.load_header_and_search_bar()

        session = SessionLocal()
        from sqlalchemy import func

        users_with_counts = (
            session.query(User)
            .join(Message, User.id == Message.sender_id)
            .filter(
                User.remove_from_display == False,
                Message.role == "user"  # Filter only "user" messages
            )
            .group_by(User.id)
            .having(func.count(Message.id) >= 12)
            .all()
        )

        for user in users_with_counts:
            self.add_user_row(
                user.id,
                decrypt_txt(user.first_name),
                decrypt_txt(user.last_name),
                user.approved
            )

        session.close()

    def load_header_and_search_bar(self):
        row = ttk.Frame(self.scroll_frame)
        row.pack(fill="x", pady=7)
        self.entry = ttk.Entry(row, width=34, bootstyle="primary")
        self.entry.pack(side="left")
        self.entry.bind("<Return>", self.search__)
        ttk.Label(row, text="", width=1).pack(side="left")
        ttk.Button(row, text="🔍", width=2, command=self.search_, bootstyle="warning").pack(side="left")
        ttk.Label(row, text="", width=1).pack(side="left")
        ttk.Button(row, text="del", width=3, command=self.delete, bootstyle="danger").pack(side="left")
        ttk.Label(row, text="", width=1).pack(side="left")
        ttk.Button(row, text="12+", width=3, command=self.above12, bootstyle="info").pack(side="left")

        row = ttk.Frame(self.scroll_frame)
        row.pack(fill="x", pady=5)
        ttk.Label(row, text="", width=1).pack(side="left")
        ttk.Label(row, text="First Name", width=14, bootstyle="info").pack(side="left")
        ttk.Label(row, text="Last Name", width=15, bootstyle="info").pack(side="left")
        ttk.Label(row, text="AI On/Off", width=12, bootstyle="primary").pack(side="left")
        ttk.Button(row, text="Refresh", width=6, bootstyle="primary", command=self.refresh_users).pack(side="left")

    def add_user_row(self, sender_id, first_name, last_name, status):
        row = ttk.Frame(self.scroll_frame)
        row.pack(fill="x", pady=5)

        ttk.Label(row, text="", width=2).pack(side="left")
        ttk.Label(row, text=first_name, width=15).pack(side="left")
        ttk.Label(row, text=last_name, width=15).pack(side="left")

        var = ttk.BooleanVar(value=(status.lower() == "yes"))

        def callback(var=var, sid=sender_id):
            self.update_user_status(sid, var.get())

        var.trace_add("write", lambda *_: callback())

        chk = ttk.Checkbutton(row, variable=var, bootstyle="success")  # green toggle
        chk.pack(side="left", padx=10)

        self.user_vars.append(((sender_id, first_name, last_name), var))


if __name__ == "__main__":
    app = UserManagerApp()
    app.mainloop()
