"""Tkinter desktop GUI for the Secure Data Vault.

A dark-themed dashboard for provisioning the PKI, starting the vault, and
storing/retrieving files as either demo user. Run with::

    python -m secure_vault.gui

No personal data is requested; the setup step provisions the neutral demo
entities (``vault``, ``user1``, ``user2``).
"""
import os
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageDraw, ImageTk  # noqa: F401 (declares the Pillow dependency)

from .ca import CertificateAuthority, setup_entities
from .client_app import VaultClient
from .config import get_ca_cert_path, get_user_dir, get_vault_dir
from .vault_server import VaultServer


class ModernButton(tk.Button):
    """A flat button with a simple hover colour effect."""

    def __init__(self, parent, **kwargs):
        # Default styling.
        kwargs.setdefault("relief", tk.FLAT)
        kwargs.setdefault("bd", 0)
        kwargs.setdefault("highlightthickness", 0)
        kwargs.setdefault("padx", 20)
        kwargs.setdefault("pady", 10)
        kwargs.setdefault("font", ("Arial", 10, "bold"))

        # Extract colours for the hover effect.
        self.default_bg = kwargs.get("bg", "#4CAF50")
        self.hover_bg = kwargs.get("hover_bg", "#45a049")
        kwargs["bg"] = self.default_bg

        if "hover_bg" in kwargs:
            del kwargs["hover_bg"]

        super().__init__(parent, **kwargs)

        # Bind hover events.
        self.bind("<Enter>", self.on_hover)
        self.bind("<Leave>", self.on_leave)

    def on_hover(self, event):
        self["bg"] = self.hover_bg
        self["cursor"] = "hand2"

    def on_leave(self, event):
        self["bg"] = self.default_bg


class AnimatedLabel(tk.Label):
    """A label with a simple fade-in animation."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.fade_in()

    def fade_in(self, alpha=0):
        if alpha < 1:
            self.configure(fg=f"#{int(255*alpha):02x}{int(255*alpha):02x}{int(255*alpha):02x}")
            self.after(50, lambda: self.fade_in(alpha + 0.1))


class SecureVaultGUI:
    """Main application window."""

    def __init__(self, root):
        self.root = root
        self.root.title("Secure Data Vault")
        self.root.geometry("1200x800")

        # Set icon and colours.
        self.setup_theme()

        # Runtime state.
        self.vault = None
        self.current_client = None
        self.current_username = None
        self.selected_file = None

        # Main container.
        self.main_container = tk.Frame(self.root, bg=self.bg_color)
        self.main_container.pack(fill="both", expand=True)

        # Build the UI.
        self.setup_ui()

        # Reflect any existing setup.
        self.check_initial_setup()

        # Start the title animation.
        self.animate_title()

    def setup_theme(self):
        """Configure the dark theme colours and ttk styles."""
        self.bg_color = "#1e1e1e"
        self.fg_color = "#ffffff"
        self.accent_color = "#00d4ff"
        self.success_color = "#4CAF50"
        self.error_color = "#f44336"
        self.warning_color = "#ff9800"
        self.card_bg = "#2d2d2d"
        self.input_bg = "#3d3d3d"

        self.root.configure(bg=self.bg_color)

        style = ttk.Style()
        style.theme_use("clam")

        # Notebook.
        style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=self.card_bg,
            foreground=self.fg_color,
            padding=[20, 10],
            font=("Arial", 10),
        )
        style.map("TNotebook.Tab", background=[("selected", self.accent_color)])

        # Frames.
        style.configure("Card.TFrame", background=self.card_bg, relief="flat", borderwidth=1)
        style.configure("Dark.TFrame", background=self.bg_color)

        # Labels.
        style.configure(
            "Heading.TLabel",
            background=self.card_bg,
            foreground=self.fg_color,
            font=("Arial", 16, "bold"),
        )
        style.configure("Card.TLabel", background=self.card_bg, foreground=self.fg_color)

        # Entries.
        style.configure(
            "Modern.TEntry",
            fieldbackground=self.input_bg,
            foreground=self.fg_color,
            borderwidth=0,
            font=("Arial", 10),
        )

    def setup_ui(self):
        """Build the header, tabbed content and status bar."""
        self.create_header()

        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.dashboard_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.dashboard_tab, text=" Dashboard ")
        self.create_dashboard_tab()

        self.setup_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.setup_tab, text=" Setup ")
        self.create_setup_tab()

        self.server_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.server_tab, text=" Server ")
        self.create_server_tab()

        self.client_tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.client_tab, text=" Client ")
        self.create_client_tab()

        self.create_status_bar()

    def create_header(self):
        """Create the title header and connection-status indicator."""
        header_frame = tk.Frame(self.main_container, bg=self.bg_color, height=100)
        header_frame.pack(fill="x", padx=20, pady=20)
        header_frame.pack_propagate(False)

        # Animated title.
        self.title_label = tk.Label(
            header_frame,
            text="Secure Data Vault",
            font=("Arial", 28, "bold"),
            bg=self.bg_color,
            fg=self.accent_color,
        )
        self.title_label.pack()

        subtitle = tk.Label(
            header_frame,
            text="Hybrid AES-256 / RSA-2048 encrypted storage",
            font=("Arial", 12),
            bg=self.bg_color,
            fg=self.fg_color,
        )
        subtitle.pack()

        # Connection status indicator.
        self.connection_frame = tk.Frame(header_frame, bg=self.bg_color)
        self.connection_frame.pack(pady=10)

        self.connection_dot = tk.Canvas(
            self.connection_frame, width=10, height=10, bg=self.bg_color, highlightthickness=0
        )
        self.connection_dot.pack(side="left", padx=5)

        self.connection_label = tk.Label(
            self.connection_frame,
            text="Disconnected",
            font=("Arial", 10),
            bg=self.bg_color,
            fg=self.fg_color,
        )
        self.connection_label.pack(side="left")

        self.update_connection_status(False)

    def create_dashboard_tab(self):
        """Create the dashboard with statistic cards and an activity log."""
        container = tk.Frame(self.dashboard_tab, bg=self.bg_color)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # Statistic cards.
        stats_frame = tk.Frame(container, bg=self.bg_color)
        stats_frame.pack(fill="x", pady=(0, 20))

        self.create_stat_card(stats_frame, "Certificates", "0", 0)
        self.create_stat_card(stats_frame, "Users", "0", 1)
        self.create_stat_card(stats_frame, "Files", "0", 2)
        self.create_stat_card(stats_frame, "Encrypted", "0", 3)

        # Activity log.
        log_frame = ttk.Frame(container, style="Card.TFrame")
        log_frame.pack(fill="both", expand=True)

        log_header = ttk.Label(log_frame, text="Activity Log", style="Heading.TLabel")
        log_header.pack(anchor="w", padx=20, pady=10)

        self.activity_tree = ttk.Treeview(
            log_frame,
            columns=("time", "user", "action", "status"),
            show="tree headings",
            height=15,
        )
        self.activity_tree.heading("time", text="Time")
        self.activity_tree.heading("user", text="User")
        self.activity_tree.heading("action", text="Action")
        self.activity_tree.heading("status", text="Status")

        self.activity_tree.column("#0", width=0, stretch=False)
        self.activity_tree.column("time", width=150)
        self.activity_tree.column("user", width=150)
        self.activity_tree.column("action", width=300)
        self.activity_tree.column("status", width=100)

        self.activity_tree.tag_configure("success", foreground=self.success_color)
        self.activity_tree.tag_configure("error", foreground=self.error_color)

        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.activity_tree.yview)
        self.activity_tree.configure(yscrollcommand=scrollbar.set)

        self.activity_tree.pack(side="left", fill="both", expand=True, padx=(20, 0), pady=(0, 20))
        scrollbar.pack(side="right", fill="y", padx=(0, 20), pady=(0, 20))

    def create_stat_card(self, parent, title, value, column):
        """Create a single statistic card and register its value label."""
        card = tk.Frame(parent, bg=self.card_bg, relief="flat", bd=1)
        card.grid(row=0, column=column, padx=10, sticky="ew")
        parent.grid_columnconfigure(column, weight=1)

        inner_frame = tk.Frame(card, bg=self.card_bg)
        inner_frame.pack(padx=20, pady=20)

        title_label = tk.Label(
            inner_frame, text=title, font=("Arial", 10), bg=self.card_bg, fg=self.fg_color
        )
        title_label.pack()

        value_label = tk.Label(
            inner_frame, text=value, font=("Arial", 20, "bold"), bg=self.card_bg, fg=self.fg_color
        )
        value_label.pack()

        # Keep a reference for later updates.
        setattr(self, f"{title.lower()}_value_label", value_label)

    def create_setup_tab(self):
        """Create the setup tab: a one-click, neutral PKI provisioning step."""
        canvas = tk.Canvas(self.setup_tab, bg=self.bg_color, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.setup_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style="Dark.TFrame")

        scrollable_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        content = tk.Frame(scrollable_frame, bg=self.bg_color)
        content.pack(fill="both", expand=True, padx=40, pady=20)

        title_frame = tk.Frame(content, bg=self.bg_color)
        title_frame.pack(pady=(0, 30))

        tk.Label(
            title_frame,
            text="Initial System Setup",
            font=("Arial", 24, "bold"),
            bg=self.bg_color,
            fg=self.fg_color,
        ).pack()

        # Information card (no personal data is collected).
        input_card = tk.Frame(content, bg=self.card_bg, relief="flat", bd=1)
        input_card.pack(fill="x", pady=20)

        input_inner = tk.Frame(input_card, bg=self.card_bg)
        input_inner.pack(padx=30, pady=30)

        tk.Label(
            input_inner,
            text=(
                "This provisions a self-signed Certificate Authority and issues\n"
                "certificates for the neutral demo entities: vault, user1 and user2.\n"
                "No personal information is required."
            ),
            font=("Arial", 11),
            justify="left",
            bg=self.card_bg,
            fg=self.fg_color,
        ).pack(anchor="w", pady=(0, 15))

        self.setup_button = ModernButton(
            input_inner,
            text="Initialize System",
            bg=self.success_color,
            fg="white",
            hover_bg="#45a049",
            font=("Arial", 12, "bold"),
            command=self.initialize_system,
        )
        self.setup_button.pack(pady=10)

        # Progress bar.
        self.setup_progress = ttk.Progressbar(content, mode="indeterminate")

        # Log card.
        log_card = tk.Frame(content, bg=self.card_bg, relief="flat", bd=1)
        log_card.pack(fill="both", expand=True)

        log_header = tk.Label(
            log_card,
            text="Setup Log",
            font=("Arial", 14, "bold"),
            bg=self.card_bg,
            fg=self.fg_color,
        )
        log_header.pack(anchor="w", padx=20, pady=(20, 10))

        log_frame = tk.Frame(log_card, bg=self.card_bg)
        log_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.setup_log = tk.Text(
            log_frame,
            height=15,
            bg=self.input_bg,
            fg=self.fg_color,
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=10,
        )
        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.setup_log.yview)
        self.setup_log.configure(yscrollcommand=log_scrollbar.set)

        self.setup_log.pack(side="left", fill="both", expand=True)
        log_scrollbar.pack(side="right", fill="y")

        self.setup_log.tag_configure("success", foreground=self.success_color)
        self.setup_log.tag_configure("error", foreground=self.error_color)
        self.setup_log.tag_configure("info", foreground=self.accent_color)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def create_server_tab(self):
        """Create the server control tab."""
        container = tk.Frame(self.server_tab, bg=self.bg_color)
        container.pack(fill="both", expand=True, padx=40, pady=20)

        control_card = tk.Frame(container, bg=self.card_bg, relief="flat", bd=1)
        control_card.pack(fill="x", pady=(0, 20))

        control_inner = tk.Frame(control_card, bg=self.card_bg)
        control_inner.pack(padx=30, pady=30)

        self.server_status_label = tk.Label(
            control_inner,
            text="Server Status: Offline",
            font=("Arial", 16, "bold"),
            bg=self.card_bg,
            fg=self.error_color,
        )
        self.server_status_label.pack(pady=10)

        button_frame = tk.Frame(control_inner, bg=self.card_bg)
        button_frame.pack(pady=20)

        self.start_server_btn = ModernButton(
            button_frame,
            text="Start Server",
            bg=self.success_color,
            fg="white",
            hover_bg="#45a049",
            command=self.start_server,
        )
        self.start_server_btn.pack(side="left", padx=10)

        self.stop_server_btn = ModernButton(
            button_frame,
            text="Stop Server",
            bg=self.error_color,
            fg="white",
            hover_bg="#d32f2f",
            command=self.stop_server,
            state="disabled",
        )
        self.stop_server_btn.pack(side="left", padx=10)

        # Server info rows.
        info_frame = tk.Frame(control_inner, bg=self.card_bg)
        info_frame.pack(fill="x", pady=10)

        self.server_info_labels = {}
        for key, label in [
            ("uptime", "Uptime"),
            ("requests", "Total Requests"),
            ("storage", "Storage Used"),
        ]:
            row = tk.Frame(info_frame, bg=self.card_bg)
            row.pack(fill="x", pady=5)
            tk.Label(
                row, text=f"{label}:", font=("Arial", 10), bg=self.card_bg, fg=self.fg_color
            ).pack(side="left")
            value_label = tk.Label(
                row, text="N/A", font=("Arial", 10, "bold"), bg=self.card_bg, fg=self.accent_color
            )
            value_label.pack(side="right")
            self.server_info_labels[key] = value_label

        # Registered users list.
        users_card = tk.Frame(container, bg=self.card_bg, relief="flat", bd=1)
        users_card.pack(fill="both", expand=True)

        users_header = tk.Label(
            users_card,
            text="Registered Users",
            font=("Arial", 14, "bold"),
            bg=self.card_bg,
            fg=self.fg_color,
        )
        users_header.pack(anchor="w", padx=20, pady=(20, 10))

        users_frame = tk.Frame(users_card, bg=self.card_bg)
        users_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.users_tree = ttk.Treeview(
            users_frame, columns=("registered", "files", "size"), show="tree headings", height=10
        )
        self.users_tree.heading("#0", text="Username")
        self.users_tree.heading("registered", text="Registered Date")
        self.users_tree.heading("files", text="Files")
        self.users_tree.heading("size", text="Total Size")

        self.users_tree.column("#0", width=200)
        self.users_tree.column("registered", width=200)
        self.users_tree.column("files", width=100)
        self.users_tree.column("size", width=150)

        users_scrollbar = ttk.Scrollbar(
            users_frame, orient="vertical", command=self.users_tree.yview
        )
        self.users_tree.configure(yscrollcommand=users_scrollbar.set)

        self.users_tree.pack(side="left", fill="both", expand=True)
        users_scrollbar.pack(side="right", fill="y")

        refresh_btn = ModernButton(
            users_card,
            text="Refresh",
            bg=self.accent_color,
            fg="white",
            hover_bg="#00a8cc",
            command=self.update_users_list,
        )
        refresh_btn.pack(pady=(0, 20))

    def create_client_tab(self):
        """Create the client tab: user selection plus store/retrieve panes."""
        container = tk.Frame(self.client_tab, bg=self.bg_color)
        container.pack(fill="both", expand=True, padx=40, pady=20)

        user_card = tk.Frame(container, bg=self.card_bg, relief="flat", bd=1)
        user_card.pack(fill="x", pady=(0, 20))

        user_inner = tk.Frame(user_card, bg=self.card_bg)
        user_inner.pack(padx=30, pady=20)

        self.user_profile_frame = tk.Frame(user_inner, bg=self.card_bg)
        self.user_profile_frame.pack(fill="x")

        profile_info = tk.Frame(self.user_profile_frame, bg=self.card_bg)
        profile_info.pack(side="left", fill="x", expand=True)

        tk.Label(
            profile_info, text="Select User:", font=("Arial", 12), bg=self.card_bg, fg=self.fg_color
        ).pack(anchor="w")

        select_frame = tk.Frame(profile_info, bg=self.card_bg)
        select_frame.pack(fill="x", pady=5)

        self.user_var = tk.StringVar()
        self.user_combo = ttk.Combobox(
            select_frame,
            textvariable=self.user_var,
            values=["user1", "user2"],
            state="readonly",
            font=("Arial", 11),
            width=20,
        )
        self.user_combo.pack(side="left", padx=(0, 10))
        self.user_combo.bind("<<ComboboxSelected>>", self.on_user_selected)

        self.connect_btn = ModernButton(
            select_frame,
            text="Connect",
            bg=self.accent_color,
            fg="white",
            hover_bg="#00a8cc",
            command=self.connect_client,
        )
        self.connect_btn.pack(side="left")

        self.disconnect_btn = ModernButton(
            select_frame,
            text="Disconnect",
            bg=self.warning_color,
            fg="white",
            hover_bg="#e68900",
            command=self.disconnect_client,
            state="disabled",
        )
        self.disconnect_btn.pack(side="left", padx=5)

        self.client_status_label = tk.Label(
            profile_info,
            text="Status: Disconnected",
            font=("Arial", 10),
            bg=self.card_bg,
            fg=self.error_color,
        )
        self.client_status_label.pack(anchor="w")

        # Operations.
        self.ops_card = tk.Frame(container, bg=self.card_bg, relief="flat", bd=1)
        self.ops_card.pack(fill="both", expand=True)

        ops_notebook = ttk.Notebook(self.ops_card)
        ops_notebook.pack(fill="both", expand=True, padx=20, pady=20)

        store_tab = ttk.Frame(ops_notebook)
        ops_notebook.add(store_tab, text="Store File")
        self.create_store_tab(store_tab)

        retrieve_tab = ttk.Frame(ops_notebook)
        ops_notebook.add(retrieve_tab, text="Retrieve Files")
        self.create_retrieve_tab(retrieve_tab)

        self.disable_client_operations()

    def create_store_tab(self, parent):
        """Create the file-storage pane."""
        container = tk.Frame(parent, bg=self.bg_color)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        self.drop_frame = tk.Frame(container, bg=self.input_bg, relief="solid", bd=2)
        self.drop_frame.pack(fill="both", expand=True, pady=(0, 20))

        drop_inner = tk.Frame(self.drop_frame, bg=self.input_bg)
        drop_inner.pack(expand=True)

        tk.Label(
            drop_inner,
            text="Select a file to encrypt and store",
            font=("Arial", 14),
            bg=self.input_bg,
            fg=self.fg_color,
        ).pack(pady=(20, 5))

        browse_btn = ModernButton(
            drop_inner,
            text="Browse Files",
            bg=self.accent_color,
            fg="white",
            hover_bg="#00a8cc",
            command=self.browse_file,
        )
        browse_btn.pack(pady=(0, 20))

        self.file_info_frame = tk.Frame(container, bg=self.bg_color)
        self.file_info_frame.pack(fill="x", pady=10)

        self.store_btn = ModernButton(
            container,
            text="Encrypt & Store",
            bg=self.success_color,
            fg="white",
            hover_bg="#45a049",
            command=self.store_file,
            state="disabled",
        )
        self.store_btn.pack()

        self.store_progress = ttk.Progressbar(container, mode="determinate")

    def create_retrieve_tab(self, parent):
        """Create the file-retrieval pane."""
        container = tk.Frame(parent, bg=self.bg_color)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        search_frame = tk.Frame(container, bg=self.bg_color)
        search_frame.pack(fill="x", pady=(0, 20))

        tk.Label(
            search_frame, text="Search:", font=("Arial", 11), bg=self.bg_color, fg=self.fg_color
        ).pack(side="left")
        search_entry = ttk.Entry(search_frame, style="Modern.TEntry", font=("Arial", 11))
        search_entry.pack(side="left", fill="x", expand=True, padx=10)
        search_entry.bind("<KeyRelease>", self.filter_files)

        files_frame = tk.Frame(container, bg=self.bg_color)
        files_frame.pack(fill="both", expand=True)

        self.files_tree = ttk.Treeview(
            files_frame,
            columns=("filename", "date", "size", "status"),
            show="tree headings",
            height=12,
        )
        self.files_tree.heading("#0", text="File ID")
        self.files_tree.heading("filename", text="Filename")
        self.files_tree.heading("date", text="Date")
        self.files_tree.heading("size", text="Size")
        self.files_tree.heading("status", text="Status")

        self.files_tree.column("#0", width=180)
        self.files_tree.column("filename", width=250)
        self.files_tree.column("date", width=150)
        self.files_tree.column("size", width=100)
        self.files_tree.column("status", width=100)

        self.files_tree.tag_configure("encrypted", foreground=self.success_color)
        self.files_tree.tag_configure("compromised", foreground=self.error_color)

        scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=self.files_tree.yview)
        self.files_tree.configure(yscrollcommand=scrollbar.set)

        self.files_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        action_frame = tk.Frame(container, bg=self.bg_color)
        action_frame.pack(fill="x", pady=20)

        ModernButton(
            action_frame,
            text="Decrypt & Download",
            bg=self.success_color,
            fg="white",
            hover_bg="#45a049",
            command=self.retrieve_file,
        ).pack(side="left", padx=5)

        ModernButton(
            action_frame,
            text="Verify Integrity",
            bg=self.accent_color,
            fg="white",
            hover_bg="#00a8cc",
            command=self.verify_integrity,
        ).pack(side="left", padx=5)

        ModernButton(
            action_frame,
            text="Refresh",
            bg="#757575",
            fg="white",
            hover_bg="#616161",
            command=self.refresh_files,
        ).pack(side="left", padx=5)

    def create_status_bar(self):
        """Create the bottom status bar."""
        status_frame = tk.Frame(self.root, bg="#161616", height=30)
        status_frame.pack(side="bottom", fill="x")
        status_frame.pack_propagate(False)

        self.status_var = tk.StringVar(value="Ready")
        self.status_label = tk.Label(
            status_frame,
            textvariable=self.status_var,
            bg="#161616",
            fg=self.fg_color,
            font=("Arial", 9),
        )
        self.status_label.pack(side="left", padx=20)

        self.activity_canvas = tk.Canvas(
            status_frame, width=20, height=20, bg="#161616", highlightthickness=0
        )
        self.activity_canvas.pack(side="right", padx=20)
        self.activity_indicator = self.activity_canvas.create_oval(
            5, 5, 15, 15, fill="#4CAF50", outline=""
        )

    def animate_title(self):
        """Kick off the title colour animation."""
        self.title_color_index = 0
        self.title_colors = ["#00d4ff", "#00ffff", "#00d4ff", "#0099cc"]
        self.update_title_color()

    def update_title_color(self):
        """Cycle the title colour on a timer."""
        if hasattr(self, "title_label"):
            self.title_label.config(fg=self.title_colors[self.title_color_index])
            self.title_color_index = (self.title_color_index + 1) % len(self.title_colors)
            self.root.after(1000, self.update_title_color)

    def update_connection_status(self, connected):
        """Update the header connection indicator."""
        color = self.success_color if connected else self.error_color
        self.connection_dot.delete("all")
        self.connection_dot.create_oval(2, 2, 8, 8, fill=color, outline="")
        self.connection_label.config(text="Connected" if connected else "Disconnected")

    def log_activity(self, user, action, status="success"):
        """Append an entry to the dashboard activity log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.activity_tree.insert(
            "", 0, values=(timestamp, user, action, status.upper()), tags=(status,)
        )
        # Keep only the last 100 entries.
        children = self.activity_tree.get_children()
        if len(children) > 100:
            self.activity_tree.delete(children[-1])

    def show_progress(self, progress_bar, duration=2000):
        """Show an indeterminate progress bar for a fixed duration."""
        progress_bar.pack(fill="x", pady=10)
        progress_bar.start()
        self.root.after(duration, lambda: [progress_bar.stop(), progress_bar.pack_forget()])

    def check_initial_setup(self):
        """Reflect whether the PKI has already been provisioned."""
        if os.path.exists(get_ca_cert_path()):
            self.setup_log.insert("end", "System already initialized\n", "success")
            self.setup_button.config(text="Re-initialize System")
            self.update_dashboard_stats()

    def update_dashboard_stats(self):
        """Recompute and display the dashboard statistics."""
        cert_paths = [
            str(get_ca_cert_path()),
            os.path.join(str(get_vault_dir()), "vault_cert.pem"),
            os.path.join(str(get_user_dir("user1")), "user1_cert.pem"),
            os.path.join(str(get_user_dir("user2")), "user2_cert.pem"),
        ]
        cert_count = sum(1 for f in cert_paths if os.path.exists(f))
        self.certificates_value_label.config(text=str(cert_count))

        if self.vault:
            self.users_value_label.config(text=str(len(self.vault.users)))

            total_files = 0
            total_size = 0
            for user in self.vault.users:
                files = self.vault.list_user_files(user)
                total_files += len(files)
                total_size += sum(f["file_size"] for f in files)

            self.files_value_label.config(text=str(total_files))
            self.encrypted_value_label.config(text=f"{total_size / 1024:.1f} KB")
        else:
            self.users_value_label.config(text="0")
            self.files_value_label.config(text="0")
            self.encrypted_value_label.config(text="0 KB")

    def initialize_system(self):
        """Provision the CA and neutral demo certificates in a worker thread."""
        if os.path.exists(get_ca_cert_path()):
            if not messagebox.askyesno(
                "Warning",
                "System already initialized. Re-initialize will delete all data. Continue?",
            ):
                return

        self.setup_log.delete(1.0, tk.END)

        self.setup_progress.pack(fill="x", pady=10)
        self.setup_progress.start()

        def setup_thread():
            try:
                self.setup_log.insert("end", "Initializing system...\n", "info")
                time.sleep(0.5)

                self.setup_log.insert("end", "Creating Certificate Authority...\n")
                ca = CertificateAuthority()
                time.sleep(0.5)

                self.setup_log.insert("end", "CA created successfully\n", "success")

                self.setup_log.insert("end", "Generating certificates for entities...\n")
                setup_entities(ca)
                time.sleep(0.5)

                self.setup_log.insert("end", "Vault certificate created\n", "success")
                self.setup_log.insert("end", "User1 certificate created\n", "success")
                self.setup_log.insert("end", "User2 certificate created\n", "success")

                self.setup_log.insert("end", "\nSetup completed successfully!\n", "success")
                self.setup_log.insert("end", "You can now start the Vault Server.\n", "info")

                self.root.after(0, self.setup_progress.stop)
                self.root.after(0, lambda: self.setup_progress.pack_forget())
                self.root.after(0, self.update_dashboard_stats)

                self.log_activity("System", "Initial setup completed", "success")

            except Exception as e:
                self.setup_log.insert("end", f"\nError: {str(e)}\n", "error")
                self.root.after(0, self.setup_progress.stop)
                self.root.after(0, lambda: self.setup_progress.pack_forget())
                self.log_activity("System", f"Setup failed: {str(e)}", "error")

        threading.Thread(target=setup_thread, daemon=True).start()

    def start_server(self):
        """Start the vault server and refresh the UI."""
        try:
            self.vault = VaultServer()
            self.vault.start_service()

            self.server_status_label.config(text="Server Status: Online", fg=self.success_color)
            self.start_server_btn.config(state="disabled")
            self.stop_server_btn.config(state="normal")
            self.status_var.set("Vault server started successfully")

            self.update_users_list()
            self.update_dashboard_stats()
            self.update_connection_status(True)

            self.log_activity("Vault", "Server started", "success")

            self.update_server_info()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
            self.log_activity("Vault", f"Server start failed: {str(e)}", "error")

    def stop_server(self):
        """Stop the vault server and refresh the UI."""
        if self.vault:
            self.vault.stop_service()
            self.vault = None

        self.server_status_label.config(text="Server Status: Offline", fg=self.error_color)
        self.start_server_btn.config(state="normal")
        self.stop_server_btn.config(state="disabled")
        self.status_var.set("Vault server stopped")

        self.update_connection_status(False)

        self.log_activity("Vault", "Server stopped", "warning")

        for label in self.server_info_labels.values():
            label.config(text="N/A")

    def update_server_info(self):
        """Periodically refresh uptime and storage figures while running."""
        if self.vault and self.vault.running:
            if not hasattr(self, "server_start_time"):
                self.server_start_time = time.time()

            uptime = int(time.time() - self.server_start_time)
            hours, remainder = divmod(uptime, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.server_info_labels["uptime"].config(
                text=f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            )

            self.server_info_labels["requests"].config(text="0")  # Placeholder.

            total_size = 0
            if os.path.exists(self.vault.storage_dir):
                for root, dirs, files in os.walk(self.vault.storage_dir):
                    for file in files:
                        if file.endswith(".enc"):
                            total_size += os.path.getsize(os.path.join(root, file))

            size_mb = total_size / (1024 * 1024)
            self.server_info_labels["storage"].config(text=f"{size_mb:.2f} MB")

            self.root.after(1000, self.update_server_info)

    def update_users_list(self):
        """Refresh the registered-users tree."""
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)

        if self.vault:
            for username, user_info in self.vault.users.items():
                files = self.vault.list_user_files(username)
                file_count = len(files)
                total_size = sum(f["file_size"] for f in files)

                reg_date = user_info["registered_at"][:10]

                self.users_tree.insert(
                    "",
                    "end",
                    text=username,
                    values=(reg_date, file_count, f"{total_size / 1024:.1f} KB"),
                )

        self.update_dashboard_stats()

    def on_user_selected(self, event):
        """Handle a change of selected user."""
        self.current_username = self.user_var.get()
        self.client_status_label.config(text=f"Selected: {self.current_username}")

    def connect_client(self):
        """Connect as the selected user, registering with the vault if needed."""
        if not self.vault:
            messagebox.showerror("Error", "Please start the Vault Server first")
            return

        if not self.current_username:
            messagebox.showerror("Error", "Please select a user")
            return

        try:
            self.current_client = VaultClient(self.current_username)

            if self.current_username not in self.vault.users:
                self.current_client.register_with_vault(self.vault)
                self.update_users_list()
                self.log_activity(self.current_username, "Registered with vault", "success")

            self.client_status_label.config(
                text=f"Connected as {self.current_username}", fg=self.success_color
            )
            self.status_var.set(f"Connected as {self.current_username}")
            self.connect_btn.config(state="disabled")
            self.disconnect_btn.config(state="normal")

            self.enable_client_operations()
            self.refresh_files()

            self.log_activity(self.current_username, "Connected to vault", "success")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}")
            self.log_activity(self.current_username, f"Connection failed: {str(e)}", "error")

    def disconnect_client(self):
        """Disconnect the current client."""
        if self.current_client:
            self.current_client = None
            self.client_status_label.config(text="Disconnected", fg=self.error_color)
            self.status_var.set("Client disconnected")
            self.connect_btn.config(state="normal")
            self.disconnect_btn.config(state="disabled")

            self.disable_client_operations()

            for item in self.files_tree.get_children():
                self.files_tree.delete(item)

            self.log_activity(self.current_username, "Disconnected from vault", "warning")

    def enable_client_operations(self):
        """Enable client operation controls."""
        self.store_btn.config(state="normal")

    def disable_client_operations(self):
        """Disable client operation controls."""
        self.store_btn.config(state="disabled")

    def browse_file(self):
        """Prompt for a file to store."""
        filename = filedialog.askopenfilename(
            title="Select file to encrypt and store",
            filetypes=[
                ("All files", "*.*"),
                ("Text files", "*.txt"),
                ("PDF files", "*.pdf"),
                ("Images", "*.png *.jpg *.jpeg"),
            ],
        )

        if filename:
            self.selected_file = filename
            self.display_file_info(filename)
            self.store_btn.config(state="normal")

    def display_file_info(self, filepath):
        """Show basic details of the selected file."""
        for widget in self.file_info_frame.winfo_children():
            widget.destroy()

        info_inner = tk.Frame(self.file_info_frame, bg=self.bg_color)
        info_inner.pack()

        file_details = tk.Frame(info_inner, bg=self.bg_color)
        file_details.pack(side="left", padx=10)

        filename = os.path.basename(filepath)
        tk.Label(
            file_details,
            text=filename,
            font=("Arial", 12, "bold"),
            bg=self.bg_color,
            fg=self.fg_color,
        ).pack(anchor="w")

        size = os.path.getsize(filepath)
        size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024*1024):.1f} MB"
        tk.Label(
            file_details, text=f"Size: {size_str}", font=("Arial", 10), bg=self.bg_color, fg=self.fg_color
        ).pack(anchor="w")

    def store_file(self):
        """Encrypt and store the selected file in a worker thread."""
        if not self.selected_file or not self.current_client:
            return

        self.store_progress.pack(fill="x", pady=10)
        self.store_btn.config(state="disabled")

        def store_thread():
            try:
                for i in range(0, 101, 10):
                    self.store_progress["value"] = i
                    time.sleep(0.1)

                success = self.current_client.store_file(self.vault, self.selected_file)

                if success:
                    self.root.after(
                        0,
                        lambda: messagebox.showinfo(
                            "Success", "File encrypted and stored successfully!"
                        ),
                    )
                    self.root.after(0, self.refresh_files)
                    self.root.after(0, self.update_dashboard_stats)

                    filename = os.path.basename(self.selected_file)
                    self.log_activity(self.current_username, f"Stored file: {filename}", "success")
                else:
                    self.root.after(
                        0, lambda: messagebox.showerror("Error", "Failed to store file")
                    )
                    self.log_activity(self.current_username, "File storage failed", "error")

            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Error: {str(e)}"))
                self.log_activity(self.current_username, f"Storage error: {str(e)}", "error")

            finally:
                self.root.after(
                    0,
                    lambda: [
                        self.store_progress.pack_forget(),
                        self.store_progress.configure(value=0),
                        self.store_btn.config(state="normal"),
                        self.clear_file_selection(),
                    ],
                )

        threading.Thread(target=store_thread, daemon=True).start()

    def clear_file_selection(self):
        """Clear the currently selected file."""
        self.selected_file = None
        for widget in self.file_info_frame.winfo_children():
            widget.destroy()
        self.store_btn.config(state="disabled")

    def refresh_files(self):
        """Reload the current user's stored-files list."""
        if not self.current_client or not self.vault:
            return

        for item in self.files_tree.get_children():
            self.files_tree.delete(item)

        files = self.vault.list_user_files(self.current_username)
        for file_info in files:
            date = file_info["stored_at"][:19]
            size = file_info["file_size"]
            size_str = (
                f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024*1024):.1f} MB"
            )

            self.files_tree.insert(
                "",
                "end",
                text=file_info["file_id"],
                values=(file_info["original_filename"], date, size_str, "Encrypted"),
                tags=("encrypted",),
            )

    def filter_files(self, event):
        """Filter the files list by the search term."""
        search_term = event.widget.get().lower()

        for item in self.files_tree.get_children():
            values = self.files_tree.item(item)["values"]
            if (
                search_term in str(values[0]).lower()
                or search_term in self.files_tree.item(item)["text"].lower()
            ):
                pass
            else:
                self.files_tree.delete(item)

        if not search_term:
            self.refresh_files()

    def retrieve_file(self):
        """Decrypt and download the selected file."""
        selected = self.files_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a file to retrieve")
            return

        file_id = self.files_tree.item(selected[0])["text"]
        filename = self.files_tree.item(selected[0])["values"][0]

        save_path = filedialog.asksaveasfilename(
            title="Save decrypted file as", defaultextension="", initialfile=filename
        )

        if save_path:
            progress_window = tk.Toplevel(self.root)
            progress_window.title("Decrypting File")
            progress_window.geometry("400x150")
            progress_window.transient(self.root)

            tk.Label(progress_window, text="Decrypting file...", font=("Arial", 12)).pack(pady=20)
            progress_bar = ttk.Progressbar(progress_window, mode="indeterminate")
            progress_bar.pack(fill="x", padx=40, pady=20)
            progress_bar.start()

            def retrieve_thread():
                try:
                    success = self.current_client.retrieve_file(self.vault, file_id, save_path)

                    self.root.after(0, progress_window.destroy)

                    if success:
                        self.root.after(
                            0,
                            lambda: messagebox.showinfo(
                                "Success", f"File decrypted and saved to:\n{save_path}"
                            ),
                        )
                        self.log_activity(
                            self.current_username, f"Retrieved file: {filename}", "success"
                        )
                    else:
                        self.root.after(
                            0, lambda: messagebox.showerror("Error", "Failed to retrieve file")
                        )
                        self.log_activity(
                            self.current_username, f"Retrieval failed: {filename}", "error"
                        )

                except Exception as e:
                    self.root.after(0, progress_window.destroy)
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Error: {str(e)}"))
                    self.log_activity(
                        self.current_username, f"Retrieval error: {str(e)}", "error"
                    )

            threading.Thread(target=retrieve_thread, daemon=True).start()

    def verify_integrity(self):
        """Verify the integrity of the selected file."""
        selected = self.files_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a file to verify")
            return

        file_id = self.files_tree.item(selected[0])["text"]
        filename = self.files_tree.item(selected[0])["values"][0]

        verify_window = tk.Toplevel(self.root)
        verify_window.title("Verifying Integrity")
        verify_window.geometry("400x200")
        verify_window.transient(self.root)

        tk.Label(verify_window, text="Verifying file integrity...", font=("Arial", 12)).pack(
            pady=20
        )

        result_frame = tk.Frame(verify_window)
        result_frame.pack(pady=20)

        def verify_thread():
            success = self.current_client.verify_file_integrity(self.vault, file_id)

            if success:
                message = "File integrity verified"
                color = self.success_color
                self.log_activity(
                    self.current_username, f"Integrity verified: {filename}", "success"
                )
            else:
                message = "File integrity check failed"
                color = self.error_color
                self.log_activity(
                    self.current_username, f"Integrity failed: {filename}", "error"
                )

                for item in self.files_tree.get_children():
                    if self.files_tree.item(item)["text"] == file_id:
                        self.files_tree.item(
                            item,
                            values=(
                                filename,
                                self.files_tree.item(item)["values"][1],
                                self.files_tree.item(item)["values"][2],
                                "Compromised",
                            ),
                            tags=("compromised",),
                        )
                        break

            tk.Label(result_frame, text=message, font=("Arial", 14), fg=color).pack()

            close_btn = ModernButton(
                verify_window,
                text="Close",
                bg="#757575",
                fg="white",
                hover_bg="#616161",
                command=verify_window.destroy,
            )
            close_btn.pack(pady=10)

        threading.Thread(target=verify_thread, daemon=True).start()


def main():
    """Launch the GUI."""
    root = tk.Tk()
    root.option_add("*Dialog.msg.font", "Arial 10")
    SecureVaultGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
