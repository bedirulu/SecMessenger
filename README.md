# ⬡ SecMessenger v3.0 — Cyber Operations Center ⬡

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Status: Operational](https://img.shields.io/badge/Status-Operational-brightgreen.svg)]()

**SecMessenger v3.0** is a high-security **Hybrid Encryption** solution that merges modern asymmetric cryptography standards with hardware-bound validation layers. This system doesn't just encrypt data; it seals it to the targeted physical hardware.

---

### 🛡️ Core Security Architecture

| Feature | Specification | Security Impact |
| :--- | :--- | :--- |
| **Encryption Type** | Hybrid RSA-2048 + AES-256-GCM | Enterprise-grade speed & security |
| **Integrity Check** | AEAD (Authenticated Encryption) | Protection against tampering & replay attacks |
| **Auth Layer** | Hardware-Bound MAC Address (AAD) | Zero-decryption on unauthorized devices |
| **Persistence** | Burn-on-Read Protocol | Automated secure file shredding post-decryption |

---

### 🚀 Mission-Critical Use Cases

* **Strategic Field Communications:** Securely transmitting intelligence from untrusted networks to HQ. Data is sealed to the HQ's MAC address, making it useless if intercepted.
* **Air-Gapped System Data Transfer:** Moving data between isolated high-security systems via physical media. Serverless architecture ensures zero internet leakage.
* **Burn-on-Read Intel Disposal:** Reading critical operational plans. The instant shredding protocol ensures no digital footprint is left if the facility is compromised.

---

### 🛠️ Strategic Tech Stack

* **Logic:** Python 3.x
* **Security Core:** `cryptography` library
* **Identity Logic:** `uuid` for Hardware-ID extraction
* **Interface:** Dark-themed "Siber Operasyon Merkezi" UI (Tkinter/TTK)

---

### ⚖️ Legal Disclaimer

> **FOR EDUCATIONAL PURPOSES ONLY.** Developed by **Bedir ULU** (MIS Student) to demonstrate advanced cryptographic concepts. The developer is not responsible for any misuse of this software.

---
*Developed by **Bedir ULU** — Aspiring Cybersecurity Specialist & Management Information Systems Student.*

# ⬡ SecMessenger v3.0 — Siber Operasyon Merkezi ⬡

**SecMessenger v3.0**, modern asimetrik kriptografi standartlarını donanım tabanlı doğrulama katmanlarıyla birleştiren, yüksek güvenlikli bir **Hibrit Şifreleme** çözümüdür. Bu sistem, sadece veriyi şifrelemekle kalmaz; veriyi hedeflenen fiziksel donanıma mühürler.

---

### 🛡️ Temel Güvenlik Mimarisi

| Özellik | Spesifikasyon | Güvenlik Etkisi |
| :--- | :--- | :--- |
| **Şifreleme Tipi** | Hibrit RSA-2048 + AES-256-GCM | Endüstriyel hız ve güvenlik |
| **Bütünlük Kontrolü** | AEAD (Kimlik Doğrulamalı Şifreleme) | Manipülasyon ve tekrar saldırılarına karşı koruma |
| **Doğrulama Katmanı** | Donanım Kilidi - MAC Adresi (AAD) | Yetkisiz cihazlarda sıfır deşifre imkanı |
| **Kalıcılık** | Okunduğunda İmha (Burn-on-Read) | Deşifre sonrası otomatik güvenli dosya silme |

---

### 🚀 Kritik Kullanım Senaryoları

* **Stratejik Saha Haberleşmesi:** Güvenli olmayan ağlar üzerinden karargaha istihbarat iletimi. Veri karargahın MAC adresine mühürlendiği için iletim sırasında ele geçirilse dahi okunamaz.
* **İzole (Air-Gapped) Sistem Veri Transferi:** İnternet erişimi olmayan sistemler arasında USB veya fiziksel medya ile veri taşıma. Sunucusuz yapı sayesinde verinin dış ağlara sızma riski yoktur.
* **Okunduğunda İmha Protokolü:** Kritik operasyonel planların okunması. Mesaj çözüldüğü an devreye giren silme protokolü, dijital iz bırakılmasını engeller.

---

### 🛠️ Stratejik Teknoloji Yığını

* **Mantık:** Python 3.x
* **Güvenlik Çekirdeği:** `cryptography` kütüphanesi
* **Kimlik Mantığı:** Donanım Kimliği (HWID) için `uuid`
* **Arayüz:** "Siber Operasyon Merkezi" Temalı UI (Tkinter/TTK)

---

### ⚖️ Yasal Uyarı

> **SADECE EĞİTİM AMAÇLIDIR.** Yönetim Bilişim Sistemleri (YBS) öğrencisi **Bedir ULU** tarafından, kriptografik mimarileri simüle etmek amacıyla geliştirilmiştir. İllegal kullanımı durumunda tüm sorumluluk kullanıcıya aittir.

---


<img width="606" height="594" alt="Ekran görüntüsü 2026-04-27 164113" src="https://github.com/user-attachments/assets/e860e92b-487a-47d3-a575-bd41260d6bc0" />
<img width="601" height="593" alt="Ekran görüntüsü 2026-04-27 164108" src="https://github.com/user-attachments/assets/13e6e3a8-a4a2-49cb-920d-2ee336981473" />
<img width="601" height="587" alt="Ekran görüntüsü 2026-04-27 164103" src="https://github.com/user-attachments/assets/c299ed9f-a202-4f27-92cc-61888a4abd9e" />
