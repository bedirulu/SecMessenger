
import os
import tkinter as tk
from tkinter import messagebox, simpledialog
import uuid

from crypto import generate_keypair, hybrid_encrypt, hybrid_decrypt, mac_to_filename

# ── Sabitler ────────────────────────────────────────────────────────────────

PRIV_KEY_FILE = "ozel_anahtar.pem"
PUB_KEY_FILE  = "acik_anahtar.pem"

# ── Yardımcı fonksiyonlar ───────────────────────────────────────────────────

def gercek_mac_al() -> str:
    mac_num = uuid.getnode()
    mac = ":".join(["{:02x}".format((mac_num >> i) & 0xFF) for i in range(0, 48, 8)][::-1])
    return mac.upper()

def log(metin: str) -> None:
    log_box.insert(tk.END, metin + "\n")
    log_box.see(tk.END)

def parola_sor(baslik: str, prompt: str) -> str | None:
    return simpledialog.askstring(baslik, prompt, show="*", parent=root)

# ── Ana işlevler ─────────────────────────────────────────────────────────────

def anahtar_uret():
    """Yeni RSA-2048 key pair üretir. Private key parola ile şifrelenir."""
    parola = parola_sor("Anahtar Üret", "Özel anahtar parolası (boş bırakma):")
    if parola is None:
        return
    if len(parola) < 6:
        messagebox.showwarning("Hata", "Parola en az 6 karakter olmalı!")
        return

    priv_pem, pub_pem = generate_keypair(password=parola)

    with open(PRIV_KEY_FILE, "wb") as f:
        f.write(priv_pem)
    with open(PUB_KEY_FILE, "wb") as f:
        f.write(pub_pem)

    log(f"[+] Key pair oluşturuldu → {PRIV_KEY_FILE} / {PUB_KEY_FILE}")
    log("[!] Özel anahtarınızı güvenli saklayın, paylaşmayın!")
    messagebox.showinfo(
        "Başarılı",
        f"Key pair oluşturuldu.\n\nAçık anahtarınızı ({PUB_KEY_FILE}) karşı tarafa gönderin."
    )

def sifrele_ve_kaydet():
    """Mesajı hedef cihazın public key'i + MAC adresi ile şifreler."""
    mesaj = mesaj_entry.get().strip()
    hedef_mac = hedef_mac_entry.get().strip()
    pub_key_dosyasi = pub_key_entry.get().strip()

    if not mesaj or not hedef_mac or not pub_key_dosyasi:
        messagebox.showwarning("Hata", "Lütfen tüm alanları doldurun!")
        return

    if not os.path.exists(pub_key_dosyasi):
        messagebox.showerror("Hata", f"Public key dosyası bulunamadı:\n{pub_key_dosyasi}")
        return

    try:
        with open(pub_key_dosyasi, "rb") as f:
            pub_pem = f.read()

        payload = hybrid_encrypt(
            plaintext=mesaj.encode("utf-8"),
            public_pem=pub_pem,
            target_mac=hedef_mac,
        )

        dosya_adi = f"giden_{mac_to_filename(hedef_mac)}.enc"
        with open(dosya_adi, "wb") as f:
            f.write(payload)

        log(f"[+] Şifrelendi → {dosya_adi}")
        messagebox.showinfo("Başarılı", f"Mesaj şifrelendi.\nDosya: {dosya_adi}")
        mesaj_entry.delete(0, tk.END)

    except Exception as e:
        log(f"[-] Şifreleme hatası: {e}")
        messagebox.showerror("Hata", str(e))

def mesaj_oku_ve_coz():
    """Mevcut cihazın MAC adresine uygun .enc dosyasını çözer ve siler."""
    if not os.path.exists(PRIV_KEY_FILE):
        messagebox.showerror("Hata", f"{PRIV_KEY_FILE} bulunamadı.\nÖnce anahtar üretin.")
        return

    parola = parola_sor("Şifre Çöz", "Özel anahtar parolası:")
    if parola is None:
        return

    su_anki_mac = gercek_mac_al()
    hedef = f"giden_{mac_to_filename(su_anki_mac)}.enc"

    if not os.path.exists(hedef):
        log(f"[!] Bu cihaz için mesaj yok. (MAC: {su_anki_mac})")
        messagebox.showinfo("Bilgi", "Bu cihaz için gelen mesaj bulunamadı.")
        return

    try:
        with open(PRIV_KEY_FILE, "rb") as f:
            priv_pem = f.read()
        with open(hedef, "rb") as f:
            payload = f.read()

        plaintext = hybrid_decrypt(
            payload=payload,
            private_key_pem=priv_pem,
            password=parola,
            mac_hint=su_anki_mac,
        )

        # Burn-on-read: dosyayı imha et
        os.remove(hedef)

        log("[!!!] MESAJ OKUNDU VE DOSYA İMHA EDİLDİ")
        log(f"[>>>] {plaintext}")
        messagebox.showinfo("Gelen Mesaj", f"Mesajınız (dosya imha edildi):\n\n{plaintext}")

    except ValueError as e:
        # AAD uyuşmazlığı veya bozuk dosya
        log(f"[-] Kimlik doğrulama hatası: {e}")
        messagebox.showerror("Hata", str(e))
    except Exception as e:
        log(f"[-] Çözme hatası: {e}")
        messagebox.showerror("Hata", f"Çözme başarısız:\n{e}")

# ── Arayüz ──────────────────────────────────────────────────────────────────

root = tk.Tk()
root.title("Siber Operasyon Merkezi v2.2")
root.geometry("520x700")
root.configure(bg="#0a0a0a")
root.resizable(False, False)

FONT_MONO  = ("Consolas", 9)
FONT_LABEL = ("Consolas", 9, "bold")
COL_BG     = "#0a0a0a"
COL_FG     = "#00ff00"
COL_GRAY   = "#888888"
COL_ENTRY  = "#111111"
COL_RED    = "#440000"
COL_GREEN  = "#003300"
COL_AMBER  = "#332200"

def entry(parent, **kw):
    return tk.Entry(parent, bg=COL_ENTRY, fg=COL_FG,
                    insertbackground=COL_FG, relief="flat",
                    font=FONT_MONO, **kw)

def btn(parent, text, cmd, color):
    return tk.Button(parent, text=text, command=cmd,
                     bg=color, fg="white", relief="flat",
                     font=FONT_LABEL, activebackground=color,
                     activeforeground=COL_FG, cursor="hand2")

def section(title):
    f = tk.LabelFrame(root, text=f"  {title}  ",
                      fg=COL_GRAY, bg=COL_BG,
                      font=FONT_LABEL, padx=12, pady=10,
                      relief="groove", bd=1)
    f.pack(padx=20, pady=(0, 10), fill="x")
    return f

def lbl(parent, text):
    tk.Label(parent, text=text, fg=COL_GRAY, bg=COL_BG,
             font=FONT_MONO, anchor="w").pack(fill="x")

# Başlık
tk.Label(root, text="◈ SECMESSENGER v2.2",
         fg=COL_FG, bg=COL_BG, font=("Consolas", 13, "bold")).pack(pady=(18, 2))
tk.Label(root, text=f"CIHAZ MAC: {gercek_mac_al()}",
         fg=COL_GRAY, bg=COL_BG, font=FONT_MONO).pack(pady=(0, 14))

# — Key pair üretimi —
f_key = section("ANAHTAR YÖNETİMİ")
btn(f_key, "YENİ RSA-2048 KEY PAIR ÜRET", anahtar_uret, COL_AMBER).pack(fill="x")
tk.Label(f_key, text="Üretilen açık anahtarı (acik_anahtar.pem) karşı tarafa gönderin.",
         fg=COL_GRAY, bg=COL_BG, font=("Consolas", 8), wraplength=440).pack(pady=(6, 0))

# — Mesaj gönder —
f_send = section("MESAJ GÖNDER")
lbl(f_send, "HEDEF MAC ADRESİ:")
hedef_mac_entry = entry(f_send)
hedef_mac_entry.pack(fill="x", pady=(2, 8))

lbl(f_send, "HEDEF PUBLIC KEY DOSYASI (.pem):")
pub_key_entry = entry(f_send)
pub_key_entry.insert(0, "acik_anahtar.pem")
pub_key_entry.pack(fill="x", pady=(2, 8))

lbl(f_send, "MESAJINIZ:")
mesaj_entry = entry(f_send)
mesaj_entry.pack(fill="x", pady=(2, 8))

btn(f_send, "ŞİFRELE VE KAYDET", sifrele_ve_kaydet, COL_RED).pack(fill="x")

# — Mesaj al —
f_read = section("MESAJ AL")
tk.Label(f_read,
         text="Bu cihazın MAC adresine gelen .enc dosyasını çözer ve imha eder.",
         fg=COL_GRAY, bg=COL_BG, font=("Consolas", 8), wraplength=440).pack(pady=(0, 8))
btn(f_read, "GELEN KUTUSU: OKU VE İMHA ET", mesaj_oku_ve_coz, COL_GREEN).pack(fill="x")

# — Log —
tk.Label(root, text="  SİSTEM LOGU", fg=COL_GRAY, bg=COL_BG,
         font=FONT_LABEL, anchor="w").pack(fill="x", padx=20)
log_box = tk.Text(root, height=9, bg="#050505", fg=COL_FG,
                  font=FONT_MONO, relief="flat", state="normal",
                  padx=8, pady=6)
log_box.pack(padx=20, pady=(2, 16), fill="x")

log("[*] Sistem aktif.")
log(f"[*] Kendi kendini imha modu: AÇIK")
log(f"[*] Şifreleme: RSA-2048 + AES-256-GCM")

root.mainloop()
