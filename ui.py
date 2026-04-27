"""
SecMessenger v3.0 — Siber Operasyon Merkezi
--------------------------------------------
• RSA-2048 + AES-256-GCM hibrit şifreleme
• Kendi anahtar çiftini oluştur / içe aktar
• Alıcının public key'ini yükle
• MAC adresine kilitli, okunduğunda dosyayı imha et
"""

import os
import uuid
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import crypto  # crypto.py (aynı klasörde)

# ═══════════════════════════════════════════════════════════
#  Renk Paleti
# ═══════════════════════════════════════════════════════════
BG        = "#0a0a0a"
BG2       = "#111111"
BG3       = "#1a1a1a"
FG        = "#e0e0e0"
GREEN     = "#00ff88"
RED       = "#ff4444"
YELLOW    = "#ffcc00"
BLUE      = "#4488ff"
BORDER    = "#2a2a2a"
FONT_MONO = ("Consolas", 9)
FONT_BOLD = ("Consolas", 10, "bold")
FONT_LG   = ("Consolas", 12, "bold")

# ═══════════════════════════════════════════════════════════
#  Yardımcı Fonksiyonlar
# ═══════════════════════════════════════════════════════════

def get_local_mac() -> str:
    mac_num = uuid.getnode()
    return ":".join(
        ["{:02x}".format((mac_num >> ele) & 0xFF) for ele in range(0, 48, 8)][::-1]
    ).upper()


def styled_button(parent, text, command, color=BG3, fg=GREEN, **kw):
    return tk.Button(
        parent, text=text, command=command,
        bg=color, fg=fg, activebackground=BORDER, activeforeground=fg,
        relief="flat", cursor="hand2", font=FONT_BOLD,
        padx=8, pady=6, **kw
    )


def styled_entry(parent, **kw):
    return tk.Entry(
        parent, bg=BG3, fg=GREEN, insertbackground=GREEN,
        relief="flat", font=FONT_MONO, **kw
    )


def styled_label(parent, text, fg=FG, **kw):
    return tk.Label(parent, text=text, bg=BG, fg=fg, font=FONT_MONO, **kw)


# ═══════════════════════════════════════════════════════════
#  Log Widget
# ═══════════════════════════════════════════════════════════

class LogBox(tk.Text):
    TAGS = {"[+]": GREEN, "[-]": RED, "[!]": YELLOW, "[*]": BLUE, "[>>>]": GREEN}

    def __init__(self, parent, **kw):
        super().__init__(
            parent, bg="black", fg=GREEN, font=FONT_MONO,
            relief="flat", state="disabled", **kw
        )
        for tag, color in self.TAGS.items():
            self.tag_config(tag, foreground=color)

    def write(self, text: str):
        self.config(state="normal")
        prefix = next((t for t in self.TAGS if text.startswith(t)), None)
        self.insert(tk.END, text + "\n", prefix)
        self.see(tk.END)
        self.config(state="disabled")


# ═══════════════════════════════════════════════════════════
#  Ana Uygulama
# ═══════════════════════════════════════════════════════════

class SecMessengerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SecMessenger v3.0 — Siber Operasyon Merkezi")
        self.root.geometry("620x780")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)

        self.local_mac = get_local_mac()
        self._build_header()
        self._build_tabs()
        self._build_log()

        self.log.write(f"[*] Sistem aktif. Cihaz: {self.local_mac}")
        self.log.write("[*] Kendi kendini imha modu AÇIK.")

    # ── Header ────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG2, pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⬡  SECMESSENGER v3.0", fg=GREEN,
                 bg=BG2, font=("Consolas", 14, "bold")).pack()
        tk.Label(hdr, text=f"CIHAZ ID: {self.local_mac}",
                 fg=YELLOW, bg=BG2, font=FONT_MONO).pack()

    # ── Tabs ──────────────────────────────────────────────────────────────

    def _build_tabs(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG2, foreground=FG,
                        font=FONT_BOLD, padding=[12, 6])
        style.map("TNotebook.Tab",
                  background=[("selected", BG3)],
                  foreground=[("selected", GREEN)])

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=16, pady=(10, 0))

        tab_keys  = tk.Frame(nb, bg=BG)
        tab_send  = tk.Frame(nb, bg=BG)
        tab_recv  = tk.Frame(nb, bg=BG)

        nb.add(tab_keys,  text="🔑 Anahtar Yönetimi")
        nb.add(tab_send,  text="📤 Gönder")
        nb.add(tab_recv,  text="📥 Al")

        self._build_keys_tab(tab_keys)
        self._build_send_tab(tab_send)
        self._build_recv_tab(tab_recv)

    # ── Tab: Anahtar Yönetimi ─────────────────────────────────────────────

    def _build_keys_tab(self, parent):
        pad = dict(padx=16, pady=6, fill="x")

        # Şifre ile koru
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(14, 0))
        styled_label(parent, "  OPSİYONEL: Özel Anahtarı Şifreyle Koru",
                     fg=YELLOW).pack(anchor="w", padx=16, pady=(8, 2))
        self.key_pass_var = tk.StringVar()
        pe = styled_entry(parent, textvariable=self.key_pass_var, show="•", width=40)
        pe.pack(**pad)

        # Oluştur butonu
        styled_button(parent, "⚡  YENİ RSA-2048 ANAHTAR ÇİFTİ OLUŞTUR",
                      self._generate_keys, color="#003300").pack(**pad)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=16, pady=8)

        # Public key göster
        styled_label(parent, "  PUBLIC KEY (paylaş):").pack(anchor="w", padx=16)
        self.pub_key_text = tk.Text(
            parent, bg=BG3, fg=GREEN, font=FONT_MONO, height=7,
            relief="flat", state="disabled"
        )
        self.pub_key_text.pack(**pad)

        styled_button(parent, "📋  Public Key'i Kopyala",
                      self._copy_pubkey).pack(**pad)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=16, pady=6)
        styled_label(parent, "  Mevcut Anahtarları İçe Aktar",
                     fg=YELLOW).pack(anchor="w", padx=16)

        btn_frame = tk.Frame(parent, bg=BG)
        btn_frame.pack(**pad)
        styled_button(btn_frame, "🔒  Private Key Yükle",
                      self._load_privkey).pack(side="left", padx=(0, 8))
        styled_button(btn_frame, "🔓  Public Key Yükle",
                      self._load_pubkey).pack(side="left")

    def _generate_keys(self):
        pw = self.key_pass_var.get().strip() or None
        try:
            priv_pem, pub_pem = crypto.generate_keypair(password=pw)
            with open("ozel_anahtar.pem", "wb") as f:
                f.write(priv_pem)
            with open("acik_anahtar.pem", "wb") as f:
                f.write(pub_pem)
            self._show_pubkey(pub_pem.decode())
            self.log.write("[+] Anahtar çifti oluşturuldu → ozel_anahtar.pem / acik_anahtar.pem")
            if pw:
                self.log.write("[+] Özel anahtar şifre ile korunuyor.")
        except Exception as e:
            self.log.write(f"[-] Anahtar oluşturma hatası: {e}")

    def _show_pubkey(self, pub_pem: str):
        self.pub_key_text.config(state="normal")
        self.pub_key_text.delete("1.0", tk.END)
        self.pub_key_text.insert(tk.END, pub_pem)
        self.pub_key_text.config(state="disabled")

    def _copy_pubkey(self):
        content = self.pub_key_text.get("1.0", tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.log.write("[*] Public key panoya kopyalandı.")

    def _load_privkey(self):
        path = filedialog.askopenfilename(
            title="Özel Anahtar Seç", filetypes=[("PEM", "*.pem"), ("Tümü", "*")]
        )
        if path:
            import shutil
            shutil.copy(path, "ozel_anahtar.pem")
            self.log.write(f"[+] Özel anahtar yüklendi: {os.path.basename(path)}")

    def _load_pubkey(self):
        path = filedialog.askopenfilename(
            title="Public Key Seç", filetypes=[("PEM", "*.pem"), ("Tümü", "*")]
        )
        if path:
            with open(path, "rb") as f:
                data = f.read()
            self._show_pubkey(data.decode())
            import shutil
            shutil.copy(path, "acik_anahtar.pem")
            self.log.write(f"[+] Public key yüklendi: {os.path.basename(path)}")

    # ── Tab: Gönder ───────────────────────────────────────────────────────

    def _build_send_tab(self, parent):
        pad = dict(padx=16, pady=6, fill="x")

        styled_label(parent, "  HEDEF MAC ADRESİ:").pack(anchor="w", padx=16, pady=(14, 2))
        self.hedef_mac_var = tk.StringVar()
        styled_entry(parent, textvariable=self.hedef_mac_var, width=40).pack(**pad)

        styled_label(parent, "  ALICININ PUBLIC KEY'İ (dosya):").pack(
            anchor="w", padx=16, pady=(8, 2))
        pubkey_frame = tk.Frame(parent, bg=BG)
        pubkey_frame.pack(**pad)
        self.pubkey_path_var = tk.StringVar(value="acik_anahtar.pem")
        styled_entry(pubkey_frame, textvariable=self.pubkey_path_var).pack(
            side="left", fill="x", expand=True)
        styled_button(pubkey_frame, "...", self._browse_pubkey_send,
                      color=BG3).pack(side="left", padx=(6, 0))

        styled_label(parent, "  MESAJINIZ:").pack(anchor="w", padx=16, pady=(8, 2))
        self.mesaj_text = tk.Text(
            parent, bg=BG3, fg=GREEN, insertbackground=GREEN,
            font=FONT_MONO, height=6, relief="flat"
        )
        self.mesaj_text.pack(**pad)

        styled_button(parent, "🔐  ŞİFRELE VE KAYDET",
                      self._sifrele, color="#440000", fg=RED).pack(**pad)

    def _browse_pubkey_send(self):
        path = filedialog.askopenfilename(
            title="Public Key Seç", filetypes=[("PEM", "*.pem"), ("Tümü", "*")]
        )
        if path:
            self.pubkey_path_var.set(path)

    def _sifrele(self):
        mesaj = self.mesaj_text.get("1.0", tk.END).strip()
        hedef_mac = self.hedef_mac_var.get().strip()
        pubkey_path = self.pubkey_path_var.get().strip()

        if not mesaj or not hedef_mac:
            messagebox.showwarning("Eksik Alan", "Lütfen tüm alanları doldurun!")
            return

        if not os.path.exists(pubkey_path):
            messagebox.showerror("Hata", f"Public key bulunamadı:\n{pubkey_path}")
            return

        try:
            with open(pubkey_path, "rb") as f:
                pub_pem = f.read()

            payload = crypto.hybrid_encrypt(
                mesaj.encode("utf-8"), pub_pem, hedef_mac
            )

            fname = f"giden_{crypto.mac_to_filename(hedef_mac)}.enc"
            with open(fname, "wb") as f:
                f.write(payload)

            self.log.write(f"[+] Şifrelendi → {fname}")
            self.log.write(f"[+] Boyut: {len(payload)} byte  (RSA+AES-GCM hibrit)")
            messagebox.showinfo("Başarılı", f"Mesaj paketlendi:\n{fname}")
        except Exception as e:
            self.log.write(f"[-] Şifreleme hatası: {e}")
            messagebox.showerror("Şifreleme Hatası", str(e))

    # ── Tab: Al ───────────────────────────────────────────────────────────

    def _build_recv_tab(self, parent):
        pad = dict(padx=16, pady=6, fill="x")

        styled_label(parent,
                     "  Özel anahtar şifre korumalıysa girin:").pack(
            anchor="w", padx=16, pady=(14, 2))
        self.recv_pass_var = tk.StringVar()
        styled_entry(parent, textvariable=self.recv_pass_var,
                     show="•", width=40).pack(**pad)

        styled_button(parent, "📡  GELEN KUTUSU TARA VE OKU",
                      self._mesaj_oku, color="#004400", fg=GREEN).pack(**pad)

        styled_label(parent, "  Çözülen Mesaj:", fg=YELLOW).pack(
            anchor="w", padx=16, pady=(12, 2))
        self.recv_text = tk.Text(
            parent, bg=BG3, fg=GREEN, font=FONT_MONO, height=8,
            relief="flat", state="disabled"
        )
        self.recv_text.pack(**pad)

    def _mesaj_oku(self):
        local_mac = self.local_mac
        local_mac_norm = crypto.mac_to_filename(local_mac)
        pw = self.recv_pass_var.get().strip() or None

        if not os.path.exists("ozel_anahtar.pem"):
            self.log.write("[-] ozel_anahtar.pem bulunamadı!")
            messagebox.showerror("Hata", "Önce anahtar çifti oluşturun.")
            return

        with open("ozel_anahtar.pem", "rb") as f:
            priv_pem = f.read()

        enc_files = [
            fname for fname in os.listdir(".")
            if fname.lower().endswith(".enc")
        ]

        if not enc_files:
            self.log.write("[-] .enc dosyası bulunamadı.")
            return

        found = False
        for fname in enc_files:
            embedded = fname.upper().replace("GIDEN_", "").replace(".ENC", "")
            if embedded != local_mac_norm:
                continue

            found = True
            self.log.write(f"[*] Eşleşen dosya bulundu: {fname}")

            try:
                with open(fname, "rb") as f:
                    payload = f.read()

                plaintext = crypto.hybrid_decrypt(payload, priv_pem, pw, local_mac)

                # Burn-on-read
                os.remove(fname)
                self.log.write("[!!!] MESAJ OKUNDU — DOSYA İMHA EDİLDİ")
                self.log.write(f"[>>>] {plaintext}")

                self.recv_text.config(state="normal")
                self.recv_text.delete("1.0", tk.END)
                self.recv_text.insert(tk.END, plaintext)
                self.recv_text.config(state="disabled")

                messagebox.showinfo(
                    "Mesaj Alındı",
                    f"Mesajınız:\n\n{plaintext}\n\n(Kaynak dosya imha edildi.)"
                )
            except ValueError as e:
                self.log.write(f"[-] Kimlik doğrulama başarısız: {e}")
                messagebox.showerror("Güvenlik Hatası", str(e))
            except Exception as e:
                self.log.write(f"[-] Çözme hatası: {e}")
                messagebox.showerror("Hata", str(e))

        if not found:
            self.log.write(f"[!] Bu cihaz ({local_mac_norm}) için dosya yok.")

    # ── Log ──────────────────────────────────────────────────────────────

    def _build_log(self):
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(8, 0))
        styled_label(self.root, "  SİSTEM LOGU", fg=YELLOW).pack(
            anchor="w", padx=16, pady=(4, 0))
        self.log = LogBox(self.root, height=8)
        self.log.pack(padx=16, pady=(2, 12), fill="x")


# ═══════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    root = tk.Tk()
    app = SecMessengerApp(root)
    root.mainloop()
