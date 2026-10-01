# macOS Advanced IP Scanner 🌐⚡

Windows'taki popüler **[Advanced IP Scanner](https://www.advanced-ip-scanner.com/tr/)** aracının macOS ekosistemi için **Go (Golang)** ile geliştirilmiş modern, hızlı ve bağımsız sürümü.

Yerel ağınızdaki (LAN) tüm cihazları saniyeler içinde tespit eder; IP, MAC adresi, donanım üreticisi (OUI), NetBIOS/mDNS cihaz adları ve açık portları listeler.

---

## 🌟 Öne Çıkan Özellikler

- 🚀 **Yüksek Hızlı Eşzamanlı Tarama:** Go goroutine havuzu (worker pool) ile tüm alt ağı (`/24` veya özel aralık) 2-3 saniyede tarar.
- 📡 **Gelişmiş Cihaz Tespiti:**
  - **Ping & TCP Probing:** ICMP ping engelli olsa bile (Windows Firewall vs.) TCP RST/SYN ve ARP yanıtlarıyla cihazı anında yakalar.
  - **MAC Adresi & OUI Üretici Tespiti:** macOS ARP tablosu entegrasyonu ve binlerce üreticiyi (Apple, Samsung, Intel, TP-Link, Xiaomi, Espressif, Cisco, Ubiquiti, HP, Canon vb.) tanıyan gömülü donanım veritabanı.
  - **Çoklu İsim Çözümleme:** mDNS / Bonjour (`.local`), NetBIOS (UDP 137 sorgusu ile Windows/Samba bilgisayar adları) ve Ters DNS (rDNS).
- 🔌 **Popüler & Derin Port Taraması:**
  - Hızlı tarama: HTTP (80/443), SSH (22), SMB (445), RDP (3389), RTSP Kamera (554), VNC (5900), Yazıcı JetDirect (9100) vb.
  - Derin tarama seçeneği (32+ servis) veya özel port aralığı (örn: `8080,3000,8000-8020`).
- 🏷️ **Akıllı Cihaz Sınıflandırma:** Yönlendirici/Modem, Bilgisayar, Mobil Cihaz, Ağ Yazıcısı, Akıllı Ev/IoT, Sunucu/NAS tespiti.
- ⚡ **Hızlı Eylemler (Quick Actions):**
  - **Tek Tıkla Web Arayüzü:** HTTP/HTTPS çalışan cihazları doğrudan tarayıcıda açma.
  - **SSH Bağlantısı:** Tek tıkla terminal SSH komutunu kopyalama.
  - **Canlı Ping Testi:** Gerçek zamanlı gecikme grafiği ve istatistiklerle ping terminali.
  - **Wake-on-LAN (WOL):** Uyuyan cihazları uzaktan uyandırmak için Magic Packet gönderme.
  - **Dışa Aktarma (Export):** Sonuçları tek tıkla **CSV**, **JSON** veya **TXT** olarak kaydetme.
- 🎨 **3 Farklı Erişim Modu:**
  1. **Modern Web Dashboard:** macOS Sonoma/Sequoia ilhamlı glassmorphism, karanlık/aydınlık tema, anlık arama ve canlı radar animasyonu.
  2. **Terminal CLI Modu:** Renkli ANSI tablo ve ilerleme çubuğu ile konsoldan tarama.
  3. **macOS .app Paketi:** Çift tıklamayla doğrudan açılan bağımsız masaüstü paketi.

---

## 📸 Ekran Görüntüleri & Görünüm

Modern koyu tema, cam efekti (glassmorphism), canlı durum göstergeleri ve macOS pencere kontrolleri ile donatılmıştır.

---

## 🛠️ Kurulum & Derleme

Sisteminizde **Go 1.20+** yüklü olması yeterlidir. Harici hiçbir kütüphane bağımlılığı yoktur (Zero Dependency).

```bash
# Depoyu klonlayın
git clone https://github.com/feritetem/macos-advance-ip-scanner.git
cd macos-advance-ip-scanner

# Derleyin
go build -o macos-advance-ip-scanner main.go
# veya
make build
```

---

## 🚀 Kullanım

### 1. Web Arayüzü ile Başlatma (Varsayılan)

```bash
./macos-advance-ip-scanner
```

Komutu çalıştırdığınızda yerel web sunucusu başlar ve varsayılan tarayıcınızda otomatik olarak açılır:
👉 **`http://localhost:7788`**

#### Kullanılabilir Parametreler:
- `-port 8080`: Web arayüzünün çalışacağı portu değiştirir.
- `-no-browser`: Tarayıcıyı otomatik açmaz (headless / sunucu kullanımı için).

---

### 2. Terminal CLI Modunda Kullanım

Web arayüzü olmadan doğrudan terminalinizde hızlı tarama yapmak için:

```bash
# Aktif arayüzü ve alt ağı otomatik algılayıp tarar:
./macos-advance-ip-scanner --cli

# Belirli bir IP aralığını taramak için:
./macos-advance-ip-scanner --range 192.168.1.1-192.168.1.254

# CIDR formatında taramak için:
./macos-advance-ip-scanner --range 192.168.254.0/24

# Özel portlar belirtmek ve CSV olarak kaydetmek için:
./macos-advance-ip-scanner --range 192.168.1.1-100 --ports 80,443,22,8080 --export csv
```

---

### 3. macOS `.app` Paketi Oluşturma

Finder veya Spotlight üzerinden doğrudan çift tıklayarak çalıştırmak için:

```bash
make app
# veya
./scripts/build-app.sh
```

Oluşturulan `dist/Advanced IP Scanner.app` uygulamasını doğrudan `/Applications` (Uygulamalar) klasörünüze taşıyabilirsiniz.

---

## 📡 REST API & Canlı Yayın (SSE)

Uygulama arka planda kendi REST API'sini ve Server-Sent Events (SSE) yayınını sunar:

| Endpoint | Metod | Açıklama |
| :--- | :---: | :--- |
| `/api/interfaces` | `GET` | Aktif ağ arayüzleri, IP'ler ve alt ağ aralıkları |
| `/api/scan/start` | `POST` | Yeni bir tarama görevi başlatır |
| `/api/scan/stop` | `POST` | Devam eden taramayı durdurur |
| `/api/scan/status` | `GET` | Mevcut durum ve bulunan cihazlar listesi |
| `/api/scan/events` | `GET` | Gerçek zamanlı tarama olayları (SSE akışı) |
| `/api/action/wol` | `POST` | Belirtilen MAC adresine Wake-on-LAN paketi iletir |
| `/api/action/ping` | `POST` | Hedef IP'ye anlık canlı ping atar |
| `/api/action/ports`| `POST` | Hedef IP üzerinde detaylı port taraması yapar |
| `/api/export` | `GET` | CSV, JSON veya TXT formatında rapor indirir |

---

## 📂 Proje Yapısı

```
macos-advance-ip-scanner/
├── cmd/
│   └── scanner/
├── pkg/
│   ├── scanner/
│   │   ├── types.go          # Veri modelleri (Host, PortInfo, ScanOptions)
│   │   ├── detector.go       # Ağ arayüzü ve alt ağ otomatik keşfi
│   │   ├── arp.go            # macOS ARP tablosu okuyucu & MAC normalleştirici
│   │   ├── oui.go            # Gömülü IEEE OUI üretici firma veritabanı
│   │   ├── ping.go           # ICMP + TCP Probe reachability motoru
│   │   ├── names.go          # NetBIOS (UDP 137), mDNS ve Reverse DNS
│   │   ├── ports.go          # Port tarayıcı & cihaz tipi sınıflandırıcı
│   │   ├── wol.go            # Wake-on-LAN sihirli paket yayınlayıcı
│   │   ├── exporter.go       # CSV, JSON ve TXT dışa aktarıcı
│   │   └── engine.go         # Eşzamanlı orkestrasyon motoru (goroutine havuzu)
│   └── server/
│       ├── server.go         # HTTP Server & SSE Hub
│       └── handlers.go       # REST API uç noktaları
├── web/
│   ├── embed.go              # //go:embed ile statik dosyaların binary'e gömülmesi
│   └── static/
│       ├── index.html        # Modern macOS arayüzü
│       ├── css/style.css     # Glassmorphism, karanlık/aydınlık tema
│       └── js/app.js         # İstemci kontrolcüsü ve dinamik filtreleme
├── scripts/
│   ├── build-app.sh          # macOS .app paketleyici
│   └── Info.plist            # macOS uygulama özellikleri
├── Makefile                  # Derleme ve yönetim kısayolları
├── .gitignore
├── go.mod
└── README.md
```

---

## 📄 Lisans

Bu proje MIT lisansı ile lisanslanmıştır.
