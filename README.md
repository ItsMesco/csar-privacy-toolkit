# CSAR Privacy Toolkit  
### Client-Side Scanning e tutela della privacy

**Autore:** Mattia Meschini  
**Università:** Alma Mater Studiorum – Università di Bologna  
**Anno accademico:** 2025–2026  
**Licenza:** Apache License 2.0  

---

## 📖 Descrizione

Questo progetto nasce come parte della tesi triennale in Informatica e si inserisce nel contesto della proposta di regolamento europeo **CSAR (Child Sexual Abuse Regulation)**, nota anche come *Chat Control*.

L’obiettivo è analizzare i meccanismi tecnici previsti per l’applicazione del **client-side scanning (CSS)** e sviluppare un toolkit open source che consenta di **preservare la privacy dell’utente finale**, mantenendo compatibilità con i requisiti di sicurezza richiesti dalla normativa.

Il progetto propone un approccio **privacy-by-design**, che minimizza i dati trasmessi, registra in modo verificabile ogni segnalazione e riduce l’esposizione dei metadati, fornendo strumenti di **auditing e trasparenza** locale.

---

## 🎯 Obiettivi principali

1. **Analizzare** l’architettura tecnica del client-side scanning e i meccanismi di attestazione del software.  
2. **Identificare** vulnerabilità e criticità dal punto di vista della privacy (leakage, sandbox bypass, metadati, verificabilità).  
3. **Progettare e sviluppare** un *Privacy Toolkit* composto da:  
   - **Egress Guard:** filtro che invia solo segnali minimali (CLEAN, MATCH_ID, ALERT_BUCKET) e registra tutto in un ledger firmato.  
   - **Privacy Ledger:** archivio append-only basato su hash chain / Merkle tree, che garantisce la tracciabilità delle segnalazioni.  
   - **Metadata Minimizer:** tool per la rimozione di EXIF e la normalizzazione dei metadati.  
   - **Audit CLI:** strumento per verificare ricevute e integrità del ledger locale.  

---

## 🧩 Architettura del sistema

[ Messaging App ]
│
▼
[ Gate di Scansione ] → [ Scanner Sandbox (no-net) ]
│ │
│ └─ Modelli/Firme RO (firmati)
▼
[ Egress Guard ] → (segnali minimali) → [ Server mock ]
│
└─► [ Privacy Ledger (Merkle + firme) ]
│
└─► [ Audit CLI ] → verifica e statistiche


Ogni evento genera un **commitment crittografico** firmato localmente. 
Nessun contenuto o feature raw lascia il dispositivo.

---

## ⚙️ Stack tecnico

- **Linguaggio:** C++20 
- **Crypto:** [libsodium](https://doc.libsodium.org/) — Ed25519, XChaCha20-Poly1305, HKDF 
- **Serialization:** Protocol Buffers / CBOR 
- **Sandbox:** [nsjail](https://github.com/google/nsjail) o [bubblewrap](https://github.com/containers/bubblewrap) con `seccomp` 
- **Database (opzionale):** SQLite per ledger 
- **Testing:** Catch2, Valgrind, ASan/UBSan 
- **Sistema target:** Linux (Ubuntu/Debian)

---

## 📊 Metriche di valutazione

| Aspetto | Metrica | Obiettivo |
|----------|----------|------------|
| **Latenza per messaggio** | Mediana / 95° percentile | ≤ 50 ms |
| **Overhead RAM** | MB aggiuntivi | ≤ 30 MB |
| **Leakage informativo** | Bit/evento | < 20 bit |
| **Falsi positivi** | Percentuale | < 2 % |
| **Verificabilità** | Coerenza ledger / ricevute | 100 % |

---

## 🚀 Istruzioni base

### Compilazione

```bash
git clone https://github.com/<username>/csar-privacy-toolkit.git
cd csar-privacy-toolkit
cmake -B build
cmake --build build -j$(nproc)
```
