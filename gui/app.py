"""
MiniPGP - Tkinter GUI.

Architecture:

    MiniPGPApp                  main window: theme, notebook, status bar
      +-- Controller            ONLY connection with the logic (core/*)
      +-- KeysTab               generating, deleting, importing/exporting, rings
      +-- SendTab               signature / encryption / compression / radix-64
      +-- ReceiveTab            decode -> decrypt -> decompress -> verify
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog

from core.keyrings import PrivateKeyRing, PublicKeyRing


# ===========================================================================
# Tema (jedno mesto za boje i fontove)
# ===========================================================================
class Theme:
    BG = "#f4f6f8"
    PANEL = "#ffffff"
    HEADER = "#1f2937"
    STATUS_BG = "#e5e7eb"

    TEXT = "#111827"
    MUTED = "#6b7280"
    WHITE = "#ffffff"
    HEADER_SUBTLE = "#d1d5db"

    ACCENT = "#2563eb"
    ACCENT_ACTIVE = "#1d4ed8"
    DANGER = "#dc2626"
    DANGER_ACTIVE = "#b91c1c"

    FONT = "Arial"
    KEY_SIZES = ["1024", "2048"]
    SYMMETRIC_ALGOS = ["AES128", "3DES"]


def apply_theme(root):
    root.configure(bg=Theme.BG)

    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure("TFrame", background=Theme.BG)
    style.configure("Panel.TFrame", background=Theme.PANEL, relief="solid", borderwidth=1)
    style.configure("TLabel", background=Theme.BG, foreground=Theme.TEXT, font=(Theme.FONT, 10))
    style.configure("Muted.TLabel", background=Theme.PANEL, foreground=Theme.MUTED, font=(Theme.FONT, 9))
    style.configure("Section.TLabel", background=Theme.PANEL, foreground=Theme.TEXT, font=(Theme.FONT, 12, "bold"))
    style.configure("Panel.TLabel", background=Theme.PANEL, foreground=Theme.TEXT)
    style.configure("TButton", font=(Theme.FONT, 10), padding=(12, 7))
    style.configure("Accent.TButton", background=Theme.ACCENT, foreground=Theme.WHITE)
    style.map("Accent.TButton", background=[("active", Theme.ACCENT_ACTIVE)])
    style.configure("Danger.TButton", background=Theme.DANGER, foreground=Theme.WHITE)
    style.map("Danger.TButton", background=[("active", Theme.DANGER_ACTIVE)])
    style.configure("TCheckbutton", background=Theme.PANEL, foreground=Theme.TEXT, font=(Theme.FONT, 10))
    style.configure("TRadiobutton", background=Theme.PANEL, foreground=Theme.TEXT, font=(Theme.FONT, 10))
    style.configure("TNotebook", background=Theme.BG, borderwidth=0)
    style.configure("TNotebook.Tab", padding=(18, 10), font=(Theme.FONT, 10, "bold"))
    style.configure("Treeview", rowheight=26, font=(Theme.FONT, 9))
    style.configure("Treeview.Heading", font=(Theme.FONT, 9, "bold"))


# ===========================================================================
# Controller - jedina tacka spajanja sa logikom (core/*)
# Sada su sve metode placeholder. Kasnije se ovde pozivaju keyrings.py /
# pipeline.py, a tabovi ostaju nepromenjeni.
# ===========================================================================
class Controller:
    def __init__(self, notify=None):
        self._notify = notify or (lambda message: None)
        self.private_ring = PrivateKeyRing()
        self.public_ring = PublicKeyRing()
        self.last_received_message = None
        self.root = None

    def set_root(self, root):
        self.root = root
    def set_notifier(self, notify):
        self._notify = notify

    def status(self, message):
        self._notify(message)

    # --- Kljucevi ---------------------------------------------------------
    def get_key_details(self, key_id):
        if not key_id:
            return None
        return self.private_ring.find(key_id) or self.public_ring.find(key_id)


    def generate_keypair(self, name, email, bits, password):
        name, email = name.strip(), email.strip()
        if not name or not email:
            messagebox.showerror("Greska", "Ime i email su obavezni.", parent=self.root)
            return
        if not password:
            messagebox.showerror("Greska", "Lozinka za privatni kljuc je obavezna.", parent=self.root)
            return
        try:
            key_id = self.private_ring.add(name, email, int(bits), password)
            self._copy_private_public_key_to_public_ring(key_id)
        except Exception as e:
            messagebox.showerror("Greska pri generisanju", str(e), parent=self.root)
            return
        self.status(f"Generisan par kljuceva (Key ID {key_id}).")

    def delete_key(self, key_id):
        if not key_id:
            messagebox.showinfo("Brisanje", "Nije izabran kljuc.", parent=self.root)
            return
        removed_private = self.private_ring.remove(key_id)
        removed_public = self.public_ring.remove(key_id)
        removed = removed_private or removed_public
        if removed:
            self.status(f"Obrisan kljuc {key_id}.")
        else:
            messagebox.showinfo("Brisanje", "Kljuc nije pronadjen.",parent=self.root)

    def import_public_pem(self, path):
        name = simpledialog.askstring("Uvoz javnog kljuca", "Ime vlasnika:", parent=self.root)
        if not name:
            return
        email = simpledialog.askstring("Uvoz javnog kljuca", "Email vlasnika:", parent=self.root)
        if not email:
            return
        try:
            key_id = self.public_ring.import_pem(path, name, email)
        except Exception as e:
            messagebox.showerror("Greska pri uvozu", str(e),parent=self.root)
            return
        self.status(f"Uvezen javni kljuc {key_id}.")

    def import_private_pem(self, path):
        file_password = simpledialog.askstring("Uvoz para", "Lozinka .pem fajla:", show="*", parent=self.root)
        if file_password is None:
            return
        name = simpledialog.askstring("Uvoz para", "Ime vlasnika:", parent=self.root)
        if not name:
            return
        email = simpledialog.askstring("Uvoz para", "Email vlasnika:", parent=self.root)
        if not email:
            return
        ring_password = simpledialog.askstring("Uvoz para", "Nova lozinka za cuvanje u prstenu:", show="*", parent=self.root)
        if not ring_password:
            return
        try:
            key_id = self.private_ring.import_pem(path, file_password, name, email, ring_password)
        except Exception as e:
            messagebox.showerror("Greska pri uvozu", str(e),parent=self.root)
            return
        self.status(f"Uvezen par kljuceva {key_id}.")

    def export_public_pem(self, key_id, path):
        if not key_id:
            messagebox.showinfo("Izvoz", "Nije izabran kljuc.",parent=self.root)
            return
        try:
            entry = self.private_ring.find(key_id) or self.public_ring.get(key_id)
            if entry is None:
                raise KeyError(f"Kljuc {key_id} nije pronadjen.")
            with open(path, "w") as f:
                f.write(entry["public_key_pem"])
        except Exception as e:
            messagebox.showerror("Greska pri izvozu", str(e),parent=self.root)
            return
        self.status(f"Izvezen javni kljuc {key_id}.")

    def export_keypair(self, key_id, path):
        if not key_id:
            messagebox.showinfo("Izvoz", "Nije izabran kljuc.",parent=self.root)
            return
        if self.private_ring.find(key_id) is None:
            messagebox.showerror("Izvoz para",
                                 "Ceo par se moze izvesti samo iz prstena privatnih kljuceva.",parent=self.root)
            return
        ring_password = simpledialog.askstring("Izvoz para", "Lozinka privatnog kljuca:", show="*", parent=self.root)
        if not ring_password:
            return
        out_password = simpledialog.askstring("Izvoz para", "Lozinka za izvezeni .pem:", show="*", parent=self.root)
        if not out_password:
            return
        try:
            self.private_ring.export_pem(key_id, path, ring_password, out_password)
        except Exception as e:
            messagebox.showerror("Greska pri izvozu", str(e),parent=self.root)
            return
        self.status(f"Izvezen par kljuceva {key_id}.")

    def list_private_keys(self):
        return self.private_ring.to_rows()

    def list_public_keys(self):
        return self.public_ring.to_rows()

    def list_private_key_choices(self):
        return [self._format_key_choice(row) for row in self.private_ring.to_rows()]

    def list_public_key_choices(self):
        return [self._format_key_choice(row) for row in self.public_ring.to_rows()]

    # --- Slanje -----------------------------------------------------------
    def send_message(self, options):
        from core.message import PgpMessage
        import os

        output_file = options["output_file"].strip()
        if not output_file:
            messagebox.showerror("Slanje", "Izlazna datoteka je obavezna.",parent=self.root)
            return

        try:
            if options["input_file"].strip():
                input_file = options["input_file"].strip()
                with open(input_file, "rb") as f:
                    data_bytes = f.read()
                filename = os.path.basename(input_file)
            else:
                data_bytes = options["message"].encode("utf-8")
                filename = "poruka.txt"

            sender_key_id = self._key_id_or_first(options["signing_key"], self.private_ring)
            recipient_key_id = self._key_id_or_first(options["recipient_key"], self.public_ring)

            if options["sign"] and sender_key_id is None:
                raise ValueError("Za potpisivanje je potreban privatni kljuc.")
            if options["sign"] and not options["sign_password"]:
                raise ValueError("Unesi lozinku privatnog kljuca za potpis.")
            if options["encrypt"] and recipient_key_id is None:
                raise ValueError("Za sifrovanje je potreban javni kljuc primaoca.")

            msg = PgpMessage.create(filename, data_bytes)
            msg.send(
                output_file,
                private_ring=self.private_ring,
                sender_public_key_id=sender_key_id,
                sender_password=options["sign_password"],
                public_ring=self.public_ring,
                recipient_public_key_id=recipient_key_id,
                algorithm=options["symmetric_algo"],
                sign=options["sign"],
                encrypt=options["encrypt"],
                compress=options["compress"],
                radix64=options["radix"],
            )
        except Exception as e:
            messagebox.showerror("Greska pri slanju", str(e),parent=self.root)
            return

        self.status(f"PGP poruka sacuvana u {output_file}.")
        messagebox.showinfo("Slanje", "PGP datoteka je uspesno kreirana.",parent=self.root)

    # --- Prijem -----------------------------------------------------------
    def receive_message(self, options):
        from core.message import PgpMessage

        input_file = options["input_file"].strip()
        if not input_file:
            messagebox.showerror("Prijem", "Ulazna PGP datoteka je obavezna.",parent=self.root)
            return

        try:
            msg, signature_ok = PgpMessage.receive(
                input_file,
                private_ring=self.private_ring,
                public_ring=self.public_ring,
                receiver_password=options["receiver_password"],
            )
        except Exception as e:
            messagebox.showerror("Greska pri prijemu", str(e),parent=self.root)
            return

        self.last_received_message = msg
        text_preview = self._message_preview(msg)
        signature_text = self._signature_text(signature_ok)
        self.status(f"PGP poruka obradjena. Potpis: {signature_text}.")
        messagebox.showinfo(
            "Prijem",
            f"Poruka je uspesno obradjena.\n\n"
            f"Fajl: {msg.filename or '-'}\n"
            f"Potpis: {signature_text}\n\n"
            f"{text_preview}",parent=self.root
        )
        return msg, signature_ok

    def save_received_message(self, path):
        path = path.strip()
        if self.last_received_message is None:
            messagebox.showinfo("Cuvanje", "Nema obradjene poruke za cuvanje.",parent=self.root)
            return
        if not path:
            messagebox.showinfo("Cuvanje", "Izaberi destinaciju za cuvanje.",parent=self.root)
            return

        try:
            with open(path, "wb") as f:
                f.write(self.last_received_message.get_data_bytes())
        except Exception as e:
            messagebox.showerror("Greska pri cuvanju", str(e),parent=self.root)
            return

        self.status(f"Originalna poruka sacuvana u {path}.")
        messagebox.showinfo("Cuvanje", "Originalna poruka je sacuvana.",parent=self.root)

    # --- Interno ----------------------------------------------------------
    def _copy_private_public_key_to_public_ring(self, key_id):
        from core.crypto import load_public_pem

        entry = self.private_ring.find(key_id)
        public_key = load_public_pem(entry["public_key_pem"].encode())
        self.public_ring.add(entry["name"], entry["email"], public_key)

    @staticmethod
    def _format_key_choice(row):
        _, key_id, name, email, bits = row
        return f"{key_id} - {name} <{email}> ({bits})"

    @staticmethod
    def _key_id_or_first(value, ring):
        value = value.strip()
        if value and value != "automatski po Key ID":
            return value.split(" ", 1)[0]
        return next(iter(ring._entries), None)

    @staticmethod
    def _signature_text(signature_ok):
        if signature_ok is None:
            return "nije potpisana"
        return "ispravan" if signature_ok else "neispravan"

    @staticmethod
    def _message_preview(msg):
        data = msg.get_data_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return f"Binarna poruka ({len(data)} bajtova)."
        if len(text) > 500:
            return text[:500] + "\n..."
        return text

    def _placeholder(self, action):
        self.status(f"Placeholder: {action}")
        messagebox.showinfo(
            "MiniPGP placeholder",
            f"Ova akcija je jos uvek placeholder.\n\nKasnije se povezuje na: {action}.",parent=self.root
        )

    @staticmethod
    def _placeholder_keys():
        return [
            ("2026-06-17 12:00", "0123ABCD89EF4567", "Alisa", "alisa@example.com", "2048"),
            ("2026-06-17 12:10", "89EF45670123ABCD", "Bob", "bob@example.com", "2048"),
        ]


# ===========================================================================
# Pomocne funkcije za izgradnju ponavljajucih widgeta
# ===========================================================================
def make_panel(parent, row, column, sticky="nsew", padding=14, padx=0):
    frame = ttk.Frame(parent, style="Panel.TFrame", padding=padding)
    frame.grid(row=row, column=column, sticky=sticky, padx=padx)
    frame.columnconfigure(0, weight=1)
    return frame


def make_section(parent, text, row, **grid):
    ttk.Label(parent, text=text, style="Section.TLabel").grid(row=row, column=0, sticky="w", **grid)


def make_muted(parent, text, row, **grid):
    ttk.Label(parent, text=text, style="Muted.TLabel").grid(row=row, column=0, sticky="w", **grid)


def make_labeled_entry(parent, label, variable, row, show=None):
    ttk.Label(parent, text=label, style="Panel.TLabel").grid(row=row, column=0, sticky="w", pady=(10, 3))
    entry = ttk.Entry(parent, textvariable=variable, show=show)
    entry.grid(row=row + 1, column=0, sticky="ew")
    return entry


def make_labeled_combo(parent, label, variable, values, row):
    ttk.Label(parent, text=label, style="Panel.TLabel").grid(row=row, column=0, sticky="w", pady=(10, 3))
    combo = ttk.Combobox(parent, textvariable=variable, values=values, state="readonly")
    combo.grid(row=row + 1, column=0, sticky="ew")
    return combo


def make_file_picker(parent, label, variable, row, on_browse):
    frame = ttk.Frame(parent, style="Panel.TFrame")
    frame.grid(row=row, column=0, sticky="ew", pady=(10, 0))
    frame.columnconfigure(1, weight=1)
    ttk.Label(frame, text=label, style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10))
    ttk.Entry(frame, textvariable=variable).grid(row=0, column=1, sticky="ew")
    ttk.Button(frame, text="Izaberi", command=on_browse).grid(row=0, column=2, padx=(8, 0))
    return frame


def make_button_grid(parent, row, buttons):
    frame = ttk.Frame(parent, style="Panel.TFrame")
    frame.grid(row=row, column=0, sticky="ew", pady=(10, 0))
    frame.columnconfigure(0, weight=1)
    frame.columnconfigure(1, weight=1)
    for index, (text, command) in enumerate(buttons):
        ttk.Button(frame, text=text, command=command).grid(
            row=index // 2, column=index % 2, sticky="ew", padx=4, pady=4
        )
    return frame


def make_info_grid(parent, row, rows):
    frame = ttk.Frame(parent, style="Panel.TFrame")
    frame.grid(row=row, column=0, sticky="ew", pady=(8, 14))
    frame.columnconfigure(1, weight=1)
    value_labels = {}
    for index, (name, value) in enumerate(rows):
        ttk.Label(frame, text=name, style="Panel.TLabel").grid(row=index, column=0, sticky="w", padx=(0, 14), pady=4)
        label = ttk.Label(frame, text=value, style="Muted.TLabel")
        label.grid(row=index, column=1, sticky="w", pady=4)
        value_labels[name] = label
    return value_labels


def make_key_tree(parent, row):
    wrapper = ttk.Frame(parent, style="Panel.TFrame")
    wrapper.grid(row=row, column=0, sticky="nsew", pady=(8, 0))
    wrapper.columnconfigure(0, weight=1)
    wrapper.rowconfigure(0, weight=1)

    columns = ("timestamp", "key_id", "name", "email", "bits")
    tree = ttk.Treeview(wrapper, columns=columns, show="headings", selectmode="browse")
    tree.grid(row=0, column=0, sticky="nsew")

    headings = {"timestamp": "Timestamp", "key_id": "Key ID", "name": "Ime", "email": "Email", "bits": "RSA"}
    widths = {"timestamp": 140, "key_id": 150, "name": 150, "email": 220, "bits": 80}
    for column in columns:
        tree.heading(column, text=headings[column])
        tree.column(column, width=widths[column], minwidth=70, stretch=True)

    scrollbar = ttk.Scrollbar(wrapper, orient="vertical", command=tree.yview)
    scrollbar.grid(row=0, column=1, sticky="ns")
    tree.configure(yscrollcommand=scrollbar.set)
    return tree


# ===========================================================================
# Tab: Kljucevi
# ===========================================================================
class KeysTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=14)
        self.controller = controller
        self._build()

    def _build(self):
        self.columnconfigure(0, weight=0, minsize=360)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        left = make_panel(self, 0, 0, sticky="nsw", padding=18)
        right = ttk.Frame(self)
        right.grid(row=0, column=1, sticky="nsew", padx=(14, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        right.rowconfigure(3, weight=1)

        self._build_generation(left)
        self._build_import_export(left)
        self._build_actions(left)
        self._build_keyrings(right)

        self.refresh_keyrings()

    def _build_generation(self, parent):
        make_section(parent, "Novi RSA par kljuceva", row=0)
        self.key_name_var = tk.StringVar()
        self.key_email_var = tk.StringVar()
        self.key_size_var = tk.StringVar(value="2048")
        self.key_password_var = tk.StringVar()

        make_labeled_entry(parent, "Ime", self.key_name_var, row=1)
        make_labeled_entry(parent, "Email", self.key_email_var, row=3)
        make_labeled_combo(parent, "Velicina RSA kljuca", self.key_size_var, Theme.KEY_SIZES, row=5)
        make_labeled_entry(parent, "Lozinka za privatni kljuc", self.key_password_var, row=7, show="*")

        ttk.Button(parent, text="Generisi par kljuceva", style="Accent.TButton",
                   command=self._on_generate).grid(row=9, column=0, sticky="ew", pady=(14, 4))
        ttk.Separator(parent).grid(row=10, column=0, sticky="ew", pady=16)

    def _build_import_export(self, parent):
        make_section(parent, "Uvoz i izvoz PEM fajlova", row=11)
        make_button_grid(parent, row=12, buttons=[
            ("Uvezi javni PEM", self._on_import_public),
            ("Uvezi privatni PEM", self._on_import_private),
            ("Izvezi javni PEM", self._on_export_public),
            ("Izvezi par kljuceva", self._on_export_keypair),
        ])
        ttk.Separator(parent).grid(row=13, column=0, sticky="ew", pady=16)

    def _build_actions(self, parent):
        make_section(parent, "Akcije nad izabranim kljucem", row=14)
        ttk.Button(parent, text="Obrisi izabrani kljuc", style="Danger.TButton",
                   command=self._on_delete).grid(row=15, column=0, sticky="ew", pady=(10, 4))

    def _build_keyrings(self, parent):
        make_section(parent, "Prsten privatnih kljuceva", row=0)
        self.private_tree = make_key_tree(parent, row=1)
        make_section(parent, "Prsten javnih kljuceva", row=2, pady=(16, 0))
        self.public_tree = make_key_tree(parent, row=3)

        make_section(parent, "Detalji izabranog kljuca", row=4, pady=(16, 0))
        self.details_text = tk.Text(parent, wrap="word", height=10, state="disabled")
        self.details_text.grid(row=5, column=0, sticky="nsew", pady=(6, 0))
        parent.rowconfigure(5, weight=1)

        self.private_tree.bind("<<TreeviewSelect>>", self._on_key_selected)
        self.public_tree.bind("<<TreeviewSelect>>", self._on_key_selected)

    # --- akcije ---
    def _on_generate(self):
        self.controller.generate_keypair(
            self.key_name_var.get(), self.key_email_var.get(),
            self.key_size_var.get(), self.key_password_var.get(),
        )
        self.refresh_keyrings()

    def _on_delete(self):
        self.controller.delete_key(self._selected_key_id())
        self.refresh_keyrings()

    def _on_import_public(self):
        path = filedialog.askopenfilename(title="Uvoz javnog kljuca")
        if path:
            self.controller.import_public_pem(path)
            self.refresh_keyrings()

    def _on_import_private(self):
        path = filedialog.askopenfilename(title="Uvoz privatnog kljuca")
        if path:
            self.controller.import_private_pem(path)
            self.refresh_keyrings()

    def _on_export_public(self):
        path = filedialog.asksaveasfilename(title="Izvoz javnog kljuca")
        if path:
            self.controller.export_public_pem(self._selected_key_id(), path)

    def _on_export_keypair(self):
        path = filedialog.asksaveasfilename(title="Izvoz para kljuceva")
        if path:
            self.controller.export_keypair(self._selected_key_id(), path)

    def _selected_key_id(self):
        for tree in (self.private_tree, self.public_tree):
            selection = tree.selection()
            if selection:
                return tree.item(selection[0], "values")[1]
        return None

    def _on_key_selected(self, event):
        tree = event.widget
        selection = tree.selection()
        key_id = tree.item(selection[0], "values")[1] if selection else None

        entry = self.controller.get_key_details(key_id)
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert(
            "1.0", self._format_entry(entry) if entry else "Nije izabran kljuc."
        )
        self.details_text.configure(state="disabled")

    @staticmethod
    def _format_entry(entry):
        lines = []
        for key, value in entry.items():
            if key == "encrypted_private":
                value = f"{value[:60]}... ({len(value)} karaktera)"
            elif key == "public_key_pem":
                value = value.strip()
            lines.append(f"{key}:\n  {value}")
        return "\n\n".join(lines)

    def refresh_keyrings(self):
        for tree, items in ((self.private_tree, self.controller.list_private_keys()),
                            (self.public_tree, self.controller.list_public_keys())):
            for row in tree.get_children():
                tree.delete(row)
            for entry in items:
                tree.insert("", "end", values=entry)


# ===========================================================================
# Tab: Slanje
# ===========================================================================
class SendTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=14)
        self.controller = controller
        self._build()

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=0, minsize=380)
        self.rowconfigure(0, weight=1)
        self._build_message_panel()
        self._build_options_panel()

    def _build_message_panel(self):
        panel = make_panel(self, 0, 0, sticky="nsew", padding=18)
        panel.rowconfigure(3, weight=1)

        make_section(panel, "Poruka za slanje", row=0)
        make_muted(panel, "Ovde se moze ucitati tekst ili fajl koji se pakuje u PGP poruku.", row=1, pady=(4, 10))

        file_row = ttk.Frame(panel, style="Panel.TFrame")
        file_row.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        file_row.columnconfigure(1, weight=1)
        self.send_input_file_var = tk.StringVar()
        ttk.Label(file_row, text="Ulazni fajl", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10))
        ttk.Entry(file_row, textvariable=self.send_input_file_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(file_row, text="Izaberi",
                   command=lambda: self._browse_open(self.send_input_file_var)).grid(row=0, column=2, padx=(8, 0))

        self.message_text = tk.Text(panel, wrap="word", height=16, undo=True)
        self.message_text.grid(row=3, column=0, sticky="nsew")
        self.message_text.insert("1.0", "Ovde ide tekst poruke...")

        output_row = ttk.Frame(panel, style="Panel.TFrame")
        output_row.grid(row=4, column=0, sticky="ew", pady=(12, 0))
        output_row.columnconfigure(1, weight=1)
        self.send_output_file_var = tk.StringVar()
        ttk.Label(output_row, text="Izlazna datoteka", style="Panel.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10))
        ttk.Entry(output_row, textvariable=self.send_output_file_var).grid(row=0, column=1, sticky="ew")
        ttk.Button(output_row, text="Sacuvaj kao",
                   command=lambda: self._browse_save(self.send_output_file_var)).grid(row=0, column=2, padx=(8, 0))

    def _build_options_panel(self):
        options = make_panel(self, 0, 1, sticky="nsew", padding=18, padx=(14, 0))

        make_section(options, "Servisi", row=0)
        self.sign_var = tk.BooleanVar(value=True)
        self.encrypt_var = tk.BooleanVar(value=True)
        self.compress_var = tk.BooleanVar(value=True)
        self.radix_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(options, text="Potpisivanje", variable=self.sign_var).grid(row=1, column=0, sticky="w", pady=(10, 2))
        ttk.Checkbutton(options, text="Enkripcija", variable=self.encrypt_var).grid(row=2, column=0, sticky="w", pady=2)
        ttk.Checkbutton(options, text="Kompresija", variable=self.compress_var).grid(row=3, column=0, sticky="w", pady=2)
        ttk.Checkbutton(options, text="Radix-64/base64 omotac", variable=self.radix_var).grid(row=4, column=0, sticky="w", pady=2)

        ttk.Separator(options).grid(row=5, column=0, sticky="ew", pady=16)

        self.signing_key_var = tk.StringVar()
        self.sign_password_var = tk.StringVar()
        self.recipient_key_var = tk.StringVar()
        self.symmetric_algo_var = tk.StringVar(value="AES128")

        make_section(options, "Autenticnost", row=6)
        self.signing_key_combo = make_labeled_combo(options, "Privatni kljuc za potpis", self.signing_key_var, [], row=7)
        make_labeled_entry(options, "Lozinka privatnog kljuca", self.sign_password_var, row=9, show="*")

        ttk.Separator(options).grid(row=11, column=0, sticky="ew", pady=16)

        make_section(options, "Tajnost", row=12)
        self.recipient_key_combo = make_labeled_combo(options, "Javni kljuc primaoca", self.recipient_key_var, [], row=13)
        make_labeled_combo(options, "Simetricni algoritam", self.symmetric_algo_var, Theme.SYMMETRIC_ALGOS, row=15)

        ttk.Separator(options).grid(row=17, column=0, sticky="ew", pady=16)

        ttk.Button(options, text="Kreiraj PGP datoteku", style="Accent.TButton",
                   command=self._on_send).grid(row=18, column=0, sticky="ew")
        self.refresh_key_choices()

    def _on_send(self):
        options = {
            "input_file": self.send_input_file_var.get(),
            "output_file": self.send_output_file_var.get(),
            "message": self.message_text.get("1.0", "end-1c"),
            "sign": self.sign_var.get(),
            "encrypt": self.encrypt_var.get(),
            "compress": self.compress_var.get(),
            "radix": self.radix_var.get(),
            "signing_key": self.signing_key_var.get(),
            "sign_password": self.sign_password_var.get(),
            "recipient_key": self.recipient_key_var.get(),
            "symmetric_algo": self.symmetric_algo_var.get(),
        }
        self.controller.send_message(options)

    def _browse_open(self, variable):
        path = filedialog.askopenfilename(title="Izbor fajla za slanje")
        if path:
            variable.set(path)

    def _browse_save(self, variable):
        path = filedialog.asksaveasfilename(title="Izbor izlazne PGP datoteke")
        if path:
            variable.set(path)

    def refresh_key_choices(self):
        self._set_combo_values(
            self.signing_key_combo,
            self.signing_key_var,
            self.controller.list_private_key_choices(),
        )
        self._set_combo_values(
            self.recipient_key_combo,
            self.recipient_key_var,
            self.controller.list_public_key_choices(),
        )

    @staticmethod
    def _set_combo_values(combo, variable, values):
        current = variable.get()
        combo["values"] = values
        if current in values:
            return
        variable.set(values[0] if values else "")


# ===========================================================================
# Tab: Prijem
# ===========================================================================
class ReceiveTab(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=14)
        self.controller = controller
        self._build()

    def _build(self):
        self.columnconfigure(0, weight=0, minsize=420)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self._build_input_panel()
        self._build_result_panel()

    def _build_input_panel(self):
        left = make_panel(self, 0, 0, sticky="nsw", padding=18)

        make_section(left, "Ulazna PGP datoteka", row=0)
        self.receive_file_var = tk.StringVar()
        make_file_picker(left, "Datoteka", self.receive_file_var, row=1,
                         on_browse=lambda: self._browse_open(self.receive_file_var))

        ttk.Separator(left).grid(row=2, column=0, sticky="ew", pady=16)

        make_section(left, "Privatni kljuc za dekripciju", row=3)
        self.receiver_key_var = tk.StringVar(value="automatski po Key ID")
        self.receiver_password_var = tk.StringVar()
        self.receiver_key_combo = make_labeled_combo(left, "Kljuc primaoca", self.receiver_key_var, ["automatski po Key ID"], row=4)
        make_labeled_entry(left, "Lozinka privatnog kljuca", self.receiver_password_var, row=6, show="*")

        ttk.Separator(left).grid(row=8, column=0, sticky="ew", pady=16)

        make_section(left, "Cuvanje originalne poruke", row=9)
        self.save_message_var = tk.StringVar()
        make_file_picker(left, "Destinacija", self.save_message_var, row=10,
                         on_browse=lambda: self._browse_save(self.save_message_var))

        ttk.Button(left, text="Obradi PGP datoteku", style="Accent.TButton",
                   command=self._on_receive).grid(row=11, column=0, sticky="ew", pady=(16, 4))
        ttk.Button(left, text="Sacuvaj originalnu poruku",
                   command=self._on_save).grid(row=12, column=0, sticky="ew", pady=4)

    def _build_result_panel(self):
        right = make_panel(self, 0, 1, sticky="nsew", padding=18, padx=(14, 0))
        right.rowconfigure(7, weight=1)

        make_section(right, "Prepoznati paketi", row=0)
        self.packet_labels = make_info_grid(right, row=1, rows=[
            ("Radix-64", "nije obradjeno"),
            ("Sesijski kljuc", "nije obradjeno"),
            ("Sifrovani podaci", "nije obradjeno"),
            ("Kompresija", "nije obradjeno"),
            ("Potpis", "nije obradjeno"),
            ("Poruka", "nije obradjeno"),
        ])

        make_section(right, "Status prijema", row=2)
        self.status_labels = make_info_grid(right, row=3, rows=[
            ("Dekripcija", "ceka obradu"),
            ("Verifikacija potpisa", "ceka obradu"),
            ("Autor potpisa", "-"),
            ("Key ID potpisnika", "-"),
            ("Originalni naziv fajla", "-"),
        ])

        make_section(right, "Originalna poruka", row=4)
        make_muted(right, "Ovde ce se prikazati plaintext nakon uspesne obrade.", row=5, pady=(4, 10))

        self.received_text = tk.Text(right, wrap="word", height=12)
        self.received_text.grid(row=7, column=0, sticky="nsew")
        self.received_text.insert("1.0", "Poruka jos nije ucitana.")

    def _on_receive(self):
        options = {
            "input_file": self.receive_file_var.get(),
            "receiver_key": self.receiver_key_var.get(),
            "receiver_password": self.receiver_password_var.get(),
        }
        result = self.controller.receive_message(options)
        if result is not None:
            msg, signature_ok = result
            self._show_received_message(msg, signature_ok)

    def _on_save(self):
        self.controller.save_received_message(self.save_message_var.get())

    def _browse_open(self, variable):
        path = filedialog.askopenfilename(title="Izbor PGP datoteke")
        if path:
            variable.set(path)

    def _browse_save(self, variable):
        path = filedialog.asksaveasfilename(title="Izbor destinacije")
        if path:
            variable.set(path)

    def refresh_key_choices(self):
        values = ["automatski po Key ID"] + self.controller.list_private_key_choices()
        current = self.receiver_key_var.get()
        self.receiver_key_combo["values"] = values
        if current not in values:
            self.receiver_key_var.set(values[0])

    def _show_received_message(self, msg, signature_ok):
        self.packet_labels["Radix-64"].configure(text="da" if msg.radix64 else "ne")
        self.packet_labels["Sesijski kljuc"].configure(text="prisutan" if msg.encrypt else "nije koriscen")
        self.packet_labels["Sifrovani podaci"].configure(text="da" if msg.encrypt else "ne")
        self.packet_labels["Kompresija"].configure(text="da" if msg.compress else "ne")
        self.packet_labels["Potpis"].configure(text="da" if msg.sign else "ne")
        self.packet_labels["Poruka"].configure(text="ucitana")

        self.status_labels["Dekripcija"].configure(text="uspesna" if msg.encrypt else "nije koriscena")
        self.status_labels["Verifikacija potpisa"].configure(text=self._signature_status(signature_ok))
        self.status_labels["Autor potpisa"].configure(text=msg.sender_public_key_id or "-")
        self.status_labels["Key ID potpisnika"].configure(text=msg.sender_public_key_id or "-")
        self.status_labels["Originalni naziv fajla"].configure(text=msg.filename or "-")

        self.received_text.delete("1.0", tk.END)
        data = msg.get_data_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = f"[Binarni sadrzaj: {len(data)} bajtova]"
        self.received_text.insert("1.0", text)

    @staticmethod
    def _signature_status(signature_ok):
        if signature_ok is None:
            return "nije potpisana"
        return "ispravan" if signature_ok else "neispravan"


# ===========================================================================
# Glavni prozor
# ===========================================================================
class MiniPGPApp(tk.Tk):
    def __init__(self, controller=None):
        super().__init__()
        self.title("MiniPGP")
        self.geometry("1180x760")
        self.minsize(1020, 680)

        self.controller = controller or Controller()
        self.controller.set_notifier(self._set_status)
        self.controller.set_root(self)

        apply_theme(self)
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

    def _build_header(self):
        header = tk.Frame(self, bg=Theme.HEADER, padx=24, pady=18)
        header.pack(fill=tk.X)
        tk.Label(header, text="MiniPGP", bg=Theme.HEADER, fg=Theme.WHITE,
                 font=(Theme.FONT, 20, "bold")).pack(anchor="w")
        tk.Label(header, text="GUI za RSA kljuceve, slanje i prijem PGP poruka",
                 bg=Theme.HEADER, fg=Theme.HEADER_SUBTLE, font=(Theme.FONT, 10)).pack(anchor="w", pady=(4, 0))

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=18, pady=18)

        self.keys_tab = KeysTab(self.notebook, self.controller)
        self.send_tab = SendTab(self.notebook, self.controller)
        self.receive_tab = ReceiveTab(self.notebook, self.controller)

        self.notebook.add(self.keys_tab, text="Kljucevi")
        self.notebook.add(self.send_tab, text="Slanje")
        self.notebook.add(self.receive_tab, text="Prijem")
        self.notebook.bind("<<NotebookTabChanged>>", self._refresh_key_choices)
        self._refresh_key_choices()

    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Spremno.")
        tk.Label(self, textvariable=self.status_var, anchor="w", padx=18, pady=8,
                 bg=Theme.STATUS_BG, fg=Theme.TEXT).pack(fill=tk.X, side=tk.BOTTOM)

    def _set_status(self, message):
        self.status_var.set(message)

    def _refresh_key_choices(self, event=None):
        self.send_tab.refresh_key_choices()
        self.receive_tab.refresh_key_choices()