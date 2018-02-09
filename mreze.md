## 1. Kompomente mreze, типови веза, примери мрежа, мреже према димензији, међумреже. 

komponente mreze:

- aplikacija : koristi mrezu
- racunar    : podrzava aplikaciju, krajnji cvor
- ruter      : prosledjuje poruke izmedju cvorova, sredisnji cvor
- veza       : spaja cvorove

tipovi veza:

- simpleks    : jedan smer, TV
- polu dupleks: u oba smera, radi-veza
- puni dupleks: u oba smera istovremeno, telefonska veza

mreze prema dimenziji:

- PAN - licne mreze, bluetooth
- LAN - lokalne mreze, WiFi, Ethernet
- MAN - gradske mreze, kablovska televizija, DSL
- WAN - regionalne mreze, racunari vlasnistvo korinsika a podmreza davaoca interneta. Prekidaci- specijalizovani raxunari koji spajaju tri ili vise linije prenosa ISP(Telekom, SBB)
- Internet

primeri mreza: WiFi, Ethernet, ISP, DSL, 2G, 3G, 4G, Bluetooth ...

medjumreze (internet):

- dobijaju se spajanjem vise razlicitih mreza 
- **Gateway** uredjaji koji fizicki povezuju i istvremeno usaglasavaju razlicite komponente (hardverske i softverske)

podela mreza prema tehnologiji prenosa:

- neusmerene(difuzno) salje signal svima
	- visesmerno salje signal nekom podskupu
- od tacke do tacke salje signal samo jednom racunar, pa on dalje

## 2. Protokoli i slojevi

Protokoli i slojevi su glavni mehanizam struktuiranja koji mrezi daje modularnost. Svaka instanca protokola komunicira sa svojim parnjakom (peer) indirektno preko slojeva koji su ispod.
Protokol predstavlja dogovor izmedju dve jedinke o tome kako treba da tece njihova medjusobna komunikacija.
Skup slojeva i protokola se naziva jednim imenom arhitektura mreze.
 
     protokol x
[ ] ------------ [ ]  sloj 1
 |   protokol y   |
[ ] ------------ [ ]  sloj 2


Poznatiji protokoli: TCP, IP, 802.11, Ethernet, HTTP, SSL, DNS ...

Protokol stek - spisak protkola koji se koriste u komunikaciji

Enkapsulacija -  mehanizam slaganja slojeva protokola (nizi slojevi nude funkcionalnosti visim skoljevima)

Statiscko multipleksiranje - deljenje mreznog protoka medju korisnicima na osnovu statistike zahteva

**Prednosti rasloavanja:**

- Prikirivanje informacija i ponovna upotreba
- Povezivanje razlicitih sistema

**Mane raslojavanja:**

- Povecani troskovi memeorije i obrade
- Prikrivanje informacija (neke aplikacije zele da zanju kako se prenose podaci)



## 3. Референтни модели протокола и слојева, јединце података, организације за стандарде.

**OSI model sa 7 slojeva:**

- Fizicki sloj - slanje bitova posalje 1 stigne 1
- Sloj veze podataka - salje okvire, usaglasavanje brzine slanja i primanja
- Mrezni sloj - rutiranje paketa, adresiranje. kako da stignu od izvora do odredista, omogucava povezivanje heterogenih mreza
- Transportni sloj - dostavljanje segmenata, obezdedjuje da svi ispravno stignu na odrediste
- Sloj sesije - upravlja sesijama. 
- Sloj prezentacije - uloga konverzije za razlicite prezentacije, bavi se sintaksom i semantikom prenetih informacija
- Sloj aplikacije - funkcije potrebne korisniku


*mane:*  slojevi sesije i prezentacije su prazni, a sloj veze i mrezni sloj su prenatrpani

**Internet referentni model:**

- Veza - fizicko slanje
- Internet - slanje paketa putem raznorodnih mreza, IP, isporucuje IP pakete
- Transport - razmena podataka izmedju cvorova (TCP, UDP)
- Aplikacija - programi koji koriste usluge mreze(FTP - dateoteke, SMTP - elektronska posta, HTTP)

*mana:* nije dovoljno uopsten, ne razdvaja fizicki sloj i sloj veze podataka


**Model sa 5 slojeva zasnovan na praksi:**

- Aplikativni (poruke)
- Transportni (segmenti)
- Mrezni      (paketi)
- Sloj veze   (okviri)
- Fizicki     (bitovi)

Nazivi nekih uredjaja u mrezi:

 - hab ili razvodnik ponavlja fizicki signal na sve izlaze  
 - svic ili skretnica usmerava pakete samo onima kojima su potrebni, znaci cita adresu 
 - ruter ili usmerivac usmerava pakete ali vodi racuna i o dobrim putanjama


## 4. Физички слој, улога, поједностављени модел, кашњења, BDP, примери.

Zaduzen za slanje pojedinacnih bitova. Signal koji se salje je analogan.
Medijum propagira signal sa informacijama u vidu bitova.
Tri osnovna tipa medija su:

 - zicani 
 - opticki (opticki kablovi) 
 - bezicni

Karakteristike kanala:

- **protok (bandwidth):** b/s oznacavamo sa B
- **kasnjenje (delay):** ozncavamo sa D

  - *kasnjenje prenosa (transmission delay):* vreme potrebno da se M-bitovna poruka postavi na komunikacioni kanal


	  		T-delay = M (b) / B (b/s) = M/B s
  - *kasnjenje propagacije (propagation delay)* vreme potrebno da bitovi prodju kroz kanal

	  		P-delay duzina_kanala / brzina_signala(~2/3 c)
  - Ukupno vreme T + P
	  


**BDP - Bandwidth delay product** BDP = B * D
Poruke zauzimaju prostor na kanalu. Kolicina podataka prisutnih na kanalu u nekom momentu je BDP. BDP = delay x bandwidth.  Meri se u bitovima i BDP je mali za kanale u lokalnim mrezama (WiFi), a veliki za velike debele kanale. 


## 5. Жичани и оптички комуникациони медијуми.

*Prednost* je sto se lako projektuje fiksni protok duz odabranih ruta.

*Mane* skup je za postavljanje, nije projektovan za mobilnost ili emitovanjem

**Zicani:**

  - **Upredena parica (UTP):** (Dve izolovane bakarne zice). Uvrtanjem se smanjuju smetnje. Uglavnom za LAN kablove i telefonske linije. Mogu da se prenose i analogni i digitalni signali
  	- upredena parica 3. kategorije dve blago uvijene zice. Obicno se grupisu 4 takva para.
  	- upredena parica 5. kategorije gusce upredene, bolje za vece razdaljine i brzu komunikaciju
  - **Koaksijalni:** Bakarno izolovano jezgro(Jezgro, izolator, bakarna mrezica, zastitni platsticni omotac). Bolja zastita, bolje performanse
  	- 50-omski - namenjen digitalnom prenosu
  	- 75-omski - koristi se kablovsku televiziju i kablovski internet
  - Vec postojece instalacije za prenos struje (nisu dobre)


**Opticki:** Dugacka, tanka i cista staklena vlakna. Ogroman protok. Velike udaljenosti. Skuplji. Izvor svetla - vlakno - foto-detektor
 
  - Visemodalno: krace, jefitinije, tanko do toga da svetlost ide pravo, samo jedan zrak
  - Unimodalno: istovremeno prolazi vise svetlosnih zrakova, do 100km


## 6. Бежични комуникациони медијуми.

Signal se emituje kroz prostor u svim pravcima. Nepoznat broj primalaca. Bliski signali (tj slicne frekvencije) se mesaju kod primaoca. Opsezi se pazljivo dodeljuju. WiFi od 3-30GHz.

*Prednosti* prirodno podrzavaju emitovanje, jeftine, jednostavne za postavljanje, podrzavaju mobilnost

*Mane* mesanje signala(mora se razresavati), jacina signala i protok izuzetno variraju.

Drugi pristup je da se ne dodeljuju frekvencije, vec da im se ogranici snaga, tako da ne ometaju jedna drugu.
ISM - za nelicencirano koriscene (daljinski za vrata, igracke, bezicni telefon koriste ISM podrucija)

- **Radio talasi** prolaze kroz zgrade, prostiru se na sve strane. VLF, LF, MF prate zakrivljenost zemlje, lako prolaze kroz zgrade. HF se odbijaju od jonosfere.
- **Mikrotalasi** veliki frekventni opseg, WiFi, iznad 100 MHz, prostiru se pravoliniski. Tornjevi ne smeju da budu previse udaljeni, ne prolaze kroz zidove. *Slabljenje zbog razlicitih putanja* zakasneli talas moze da dodje u suprotnu fazu sa direktnim talasom i tako ga ponisti
- **svetlosni signali** iznad zgrada

## 7. Komunikacioni sateliti

Sateliti su efikasni za emitovanje i komunikaciju bilo kada i bilo gde. Pojacavaju primljen signal i ponovo ga emituju na drugoj frekvenciji.

*Prednosti* cena prenete poruke ne zavisi od udaljenosti.

*Mane* losi sa aspekta bezbednosti, svako moze da cuje.

Tipovi:

- *geostacionarni (GEO):* na 35000km, VAST(Very Small Aperture Terminals) VAST-hub-satelit- vise VAST-ova
- *srednje-orbitalni (MEO)*
- *nisko-orbitalni (LEO):* brzi odziv itd, Teledesic

## 8. Сигнали, пренос, фреквенциона репрезентација, сигнал у жичаним, оптичким, бежичним медијумима.

Signal kroz vreme se moze predstaviti putem svojih frekvencijskih delova.
Manji skup frekvencija -> manji protok
Opseg frekvencija koje se prenose bez ve¢eg slabljenja naziva se propusni opseg



**Signal u zicanim medijumima** kasni (2/3c), slabi (neke freq vise), sum

**Signal u optickim medijumima** se prenosi sa malim gubitkom u tri siroka freq opsega

**Signal u bezicnim komunikacijama** putuje brzo ali slabi sa kvadratom rastojanja. Koristi se signal nosac. Visestruki signali na istoj freq se mesaju. Mogu se koristiti iste freq ako su razdaljine velike. Propagacija zavisi od okruzenja. Problem sabiranja odbijenih talasa.


## 9. Модулација и мултиплексирање сигнала.

**erudijum36 eksplozivni svemirski modulator :D**

**BASEBAND** (signal se direktno postavlja na zicu, iste freq dig i anal signala):

- Jednostavna modulacija: visok napon 1, niski 0 - NRZ
- Dilema oko broja nula - sinhronizacija satova, mancestersko kodiranje
- NRZI(Non-Return-To-Zero-Inverted) - koristimo 1 za prelazak signala, a 0 ako nema prelaska
- 4B/5B - svaka 4 bita se prosire na 5, sa fiksnom tabelom za prevodjenje bez dugackih nizova nula, inverzija signala na jedinici kako bi se izbegli dugacki nizovi jedinica

**PASSBAND** (optika i wireless) - modulacija preko signala nosaca: 
Signal nosac oscilira na zeljenoj freq a onda se modulira promenom amplitude, freq ili faze.

**Multipleksiranje** se bavi deljenjem kanala izmedju vise korisnika.


- **frekvenciono (FDM):** razliciti korisnici na razl freq 
- **vremensko (TDM):** kao timesharing
- **kodno (CDMA):** korisnici dobijaju kljuceve ortogonalne medju sobom. Zbirni signal se skalarno mnozi sa kljucem posiljaoca i dobija se informacija o tome sta je poslao


## 10. Природна ограничења преноса сигнала.

O tome koliko se cesto moze slati podatak kroz kanal...

B - protok(bitrate), S - jacina signala, N - jacina suma

B ogranicava promenu frekvencije, S i N ogranicavaju broj razlcivih nivoa

**Najkvistov limit**: Max broj promena simbola je 2B. 2B je donja granica za sample rate. Ako postoji V nivoa signala (bez suma), onda je max protok

R = 2Blog2(V)  b/s
jednacina za maksimalnu brzinu prenosa kroz besumni kanal ogranicene propusne moci.

**Senonov kapacitet**: 
Prosirenje Najkvistove jednacine na kanale sa slucajnim, tj. termickim sumom
Broj razlucivih nivoa signala zavisi od odnosa jacina signala i suma S/N -> SNR.
SNR se meri u dB(decibeli) = 10log10(S/N).

Senonova jednacina:

C = Blog2(1 + S/N)  b/s

Kod zica i optike se moze projektovati ciljni SNR pa i B.
Kod bezicnih kanala SNR drasticno varira za dato B.

## 11. Преглед релевантнијих система комуникација.

**Sistem fiksne telefonije:** 

  - hijerarhijski sistem za prenos govora
  - lokalne konekcije najcesce koriste upredene parice
  - medjumesne najcesce opticki kablovi
  - centrale preusmeravaju i odrzavaju konekcije
  - putem ovog sistema se realizuje DSL

**Sistem mobilne telefonije:**

  - 1G: analogni glas - FM modulacija
  - 2G: digitalni glas - GSM, QPSK modulacija
  - 3G: digitalni glas i podaci - UMTS, CDMA
  - 4G: digitalni glas i podaci - LTE, OFDM (naprednija FDM)
  
Celijske jedinice razlicitih frekvencija (nesusedne mogu imati istu freq)

Internet preko kablovske: Freq opsezi koje TV ne koristi se koriste za download ili upload.

Kablovska koristi coax kablove, salje podatke svima i deli protok.

ADSL ne deli protok, nema mogucnost emitovanja i koristi upredene parice.


## 12. Слој везе, улога, комуникација са слојем испод и изнад, кратко објашњење списка активности на слоју везе. 


Radi sa okvirima. Prenosi okvire putem jednog ili vise povezanih komunikacionih kanala. Okviri su fiksne velicine.

Funkcije:

- uokvirivanje (zaglavlje, poruka, zavrsetak)
- detekcija i korekcija gresaka
- retransmisija i kontrola toka
- ponovno slanje u slucaju gubitka okvira
- razresavanje duplikata
- usaglasavanje brzina posiljaoca i primaoca


## 13. Уоквиривање у слоју везе.

Uokvirivanje se bavi time sta se stavlja na vrh okvira, odnosno u zaglavlje.

**Metode uokvirivanja:**

- **brojanje bajtova (debilan)**
 	- svaki sloj zapocinje podatkom o duzini, ako se desi greska, rip


- **umetanje bajtova** 
	- specijalnu sekvencu koja oznazava pocetak okvira 
 	- indikatorska oznaka u vidu jednog bajta koja oznacava pocetak/kraj okvira
 	- ideja sa esc kodovima ako se nalazi i unutar poruke


- **umetanje bitova**
	-  sad ne vrsimo parsiranje bajt po bajt, nego bit po bit
 	- neka je indikator 6 jedinica, onda bi se nakon svakih 5 jedinica umetnula nula kako bi se razlikovala od indikatora (stuffed bits)


## 14. Кодирање грешака у слоју везе.

Zbog raznih sumova moze doci do gresaka na nekim bitovima.

Tipovi gresaka:

- **ravnoerna** nastaje zbog suma (npr. jedan na svakih hiljadu bitova)
- **rafalna** javlja se na velikom broju uzastopnih bitova, zbog varnicenja

Pristup dodavnja redudantnosti:

- **detekcija** - dodavanje kontrolnih bitova ili naivan pristup saljem sve x2
- **korekcija** - dodavanje jos bitova koji omogucuju korekciju
- (retransmisija)

Kodna rec se sastoji od D bitova i R kontrolnih bitova (R = f(D)). 
Posiljalac racuna R i salje poruku (svih D+R bitova)
Primalac prihvata D+R bitova, racuna f(D) i poredi da li je to sto je dobio isto kao i R.

#### Hamingovo rastojanje

Hamingovo rastojanje je minimalan broj inverzija bitova potrebnih da se od jedne reci dobije neka druga rec. 
Ideja je da skup validnih reci bude dosta manji od skupa svih mogucih reci.
Zato ce greska na jednom bitu imati male sanse da bude validna.

Za detekciju do N gresaka, HR mora biti barem N+1
Za korekciju do N gresaka, HR mora biti barem 2N+1


## 15. Детекција грешака у слоју везе. --------------------

Detekcija omogu¢ava samo indirektnu popravku jer zahteva retransmisiju. Koristimo tri algoritma u praksi: 
	
- provera parnosti
- kontrolni zbirovi
- ciklicne provere redudanse CRC


**Provera parnosti**

 D + 1 bit - suma D bitova po modulu 2, lose readi za rafalne greske

**Kontrolni zbirovi**

Koriste se za rafalne greske.
Sumiranje po kolonama D + N bitova - koristi se u TCP/IP/UDP

konretna implementacija **Internet kontrolni zbir**: 

  nepotpuni komplement, 2 reprezentacije nule, jedna da oznaci da zbir ne postoji
  kontrolni zbir ima 16b i predstavlja nepotpuni komplement sume reci po kolonama
  
  **slanje:** 

  - podaci se sloze kao 16b reci
  - na kontrolni zbir postavimo nule
  - sabiramo sve, a eventualne prenose prebacujemo na pocetak
  - negiramo dobijenu sumu
  

  **primanje:**

  - sloziti podatke kao 16b reci (ukljucujuci i kontrolni zbir)
  - sabiramo sve, eventualni prenos dodajemo na najnizi bit
  - negiramo rezultat i proverimo da li je 0

**CRC**

Koristi se i za rafalne i za ravnomerne greske.

Sekvenca bitova se smatra polinomom ciji su koef nule i jedinice.
 Za datih N bitova generisemo K kontrolnih bitova tako da polinom sa N+K bitova bude deljiv nekim unapred odabranim polinomom C (generator)  
 koristi se u Ethernet, 802.11, ADSL, cable...
 
**slanje:**
 
- prosirimo Nbitni podatak sa K nula
- podelimo sa C
- zadrzimo ostatak
- dodamo ostatak na prosireni broj

**primanje:**

  - podeliti poruku sa C i videti da li je ostatak jednak nuli


## 16. Корекција грешака у слоју везе.

Detekcija se koristi kada su greske neocekivane i velike, a korekcija kada su greske ocekivane i nema vremena za retransmisiju.


pod pretpostavkom da se moze desiti samo jednobitna greska, mozemo da ispravimo rec tako sto je mapiramo u najblizu (po HR) validnu rec
ovo radi ako je HR > 2d+1 gde je d max broj ocekivanih 1b gresaka

Hamingovi kodovi za korekciju:

- koristi se n biova podataka i k kontrolnih bitova n = 2^k - k - 1
- kontrolni bitovi se stavljaju na pozicije 1, 2, 4 ...
- kontrolni bit na poziciji i se racuna kao bit parnosti za bitove cije pozicije u binarnoj reprezentaciji imaju 1 na i-tom mestu
- dekodiranje: primalac radi isto ovo, zatim slozi dobijene bitove kao binarni broj (sindrom). Taj broj daje poziciju greske. Korekcija podrazumeva invertovanje bita na toj poziciji

U praksi se koriste:

- Konvolucioni kodovi
- LDPC - low density parity check
- Rid-Solomonovi kodovi


## 17. Слој везе, типови сервиса, окружење, утопијски једносмерни протокол.

**Tipovi servisa:**

- **bez uspostave veze i bez potvrde prijema:** okvir se salje bilo kojim redosledom i bez retransmisije u slucaju greske. npr ethernet
- **bez uspostave veze sa potvrdom prijema:** radi se retransmisija po potrebi. Dobijamo potvrdu da je stigao, npr wifi
- **sa uspostave veze i sa potvrdom prijema:** podaci se primaju istim redom koji su i poslati, retko se koristi


Sloj veze je delom realizovan na mreznoj kartici a delom na OS.

**Prema mreznom sloju i prema fizickom**

- smao jednom dobijem paket i samo jednom ga posaljem mreznom sloju
- baferisem pakete ako treba opet da se salju na drugu stranu

**Osnovni protokoli:**

- utopijski jednosmerni protokol
- "stani i cekaj" za kanal bez gresaka
- "stani i cekaj" za kanal sa greskama

**Utopijski jednosmerni protokol:**

Koristi ga Ethernet. 

- ne predvidja pojavu greske
- primalac je jednako brz kao i posiljalac
- prenos podataka je jednosmeran

- uzmem paket po paket od mreznog sloja
- pravim okvir i prosledjujem fizickom
- isto i kad primam

## 18. Контрола тока, ARQ, паузе (тајмаути), дупликати, протокол „стани и чекај“ за савршен и несавршен канал.

Ukoliko su razlicite brzine posiljaoca i primaoca -> kontrola toka.

Kontrola toka je sinhronizacija komunikacije izmedju posiljaoca i primaoca.

**Protokol stani i cekaj za savrsen kanal:** Pretpostavljamo da je kanal savrsen, nema gresaka ni izgubljenih okvira. Primalac salje prazan okvir kad je spreman da nastavi -ACK. Salje se okvir po okvir


Ako kanal nije savrsen, mogu se pojaviti greske, izgubiti okviri ili pojaviti duplikati.

**ARQ - automatic repeat request:** 

- Koristi se kada su greske uobicajene i moraju se ispraviti (WiFi, TCP)
- Primalac salje potvrdu (ACK). 
- Posiljalac salje opet automatski posle timeout ako ne stigne ACK. 
- Kolika da bude pauza? Kako izbeci duplikate? Koriste se indikatori okvira (1 bit). 

**Protokol stani i cekaj za nesavrsen kanal:**

- Posaljilac salje okvir, i ceka na potvrdu, proverava da li je potvrda dobra
- Primalac uzima samo onaj okvir koji ocekuje i salje potvrdu za trenutni okvir
- Neefikasan, u datom trenutku samo jedan paket prolazi korz kanal

## 19. Протокол клизних прозора у слоју везе, „1-битни“, „врати се N“, „селективно понављање“.

**Protokol kliznih prozora**

Uopstenje "stani i cekaj" protokola, omogucava da u jednom trenutku na kanalu bude N okvira. Posiljalac ima N uzastopnih okvira koje treba da posalje, baferuje ih zbog eventualne retransmisije. Kako pristizu ACK, posiljalac pomera spisak okvira (prozor)

Optimalno N zavisi od BDP, N >= 2BD+1

- **1-bitni** protokol kliznih prozora velicine 1. Nema odvojenih algoritama za posaljioca i priaoca. Za ACK koristimo okvir iz drugog pravca. Neefikasan ako obe strane krenu da salju u isto vreme
- **vrati se N** primalac prihvata samo okvire koji stizu redom, odbacuje sve ostale. Posiljalac ponovo salje sve nepotvrdjene prozore. Jednostavan na strani primaoca bafer samo za jedan okvir. Nepotrebno trosenje prozora u slucaju velikih prozora
- **selektivno ponavljanje** primalac prihvata okvire sve dok je redni broj okvira u opsegu definisanom kliznim prozorom. Slozeniji za implementaciju, efikasnija upotreba protoka. Opseg brojeva okvira mora biti barem dva puta veci od velicine prozora

## 20. MAC подслој, улога, алокација канала, ALOHA протокол.

MAC podsloj je zaduzen za odredjivanje ko ce korititi kanal kada ima vise zahteva (mreza koristi neusmereno emitovanje). Protokoli kojima se odredjuje ko ce sledeci koristiti kanal pripadaju MAC podsloju sloja veze. Posebno vazan za lokalne mreze sa slobodnim pristupanjem.

Alokacija kanala:

- staticka (multipleksiranje podelom frekvencije, mult. podelom vremena)
- dinamicka

Ovde je rec o dinamickoj alokaciji kanala.

**ALOHA:**

mreza koja je povezivala havajska ostrva 60tih. Ne oslusuje se mreza pre slanja.

- **cista ALOHA** 
 
	- cvor salje kad ima nesto da posalje
	- ako se desi kolizija (nema ACK), ceka se random vreme i salje se opet
	- jednostavan protokol, decentralizovan
	- radi dobro ako je malo opterecenje
	- nije efikasan kad je visoko opterecenje


- **vremenska ALOHA**

	- sinhronizacija globalnog vremena
	- jedna stanica u predodredjenom intervalu salje poseban signal
	- emitovanje je dozvoljeno samo na pocetku intervala

insipiracija za ethernet

## 21. CSMA, CSMA/CD, BEB.

Koristimo protokole za pristup uz osluskivnaje saobracaja na nosiocu podataka. Ne garantuje da nece biti kolizija, zbog kasnjenja

**CSMA (Carrier Sense Multiple Access)**

- poboljsavanje ALOHA protokola osluskivanjem kanala pre slanja
- ako je kanal slobodan salje, ako ne ceka
- jednostavno za zicane , a ne za bezicne kanale
- moguce su i dalje greske zbog kasnjenja
- dobar protiv kolizija ako je bdp mali

- **povremeni CSMA** - kad utvrdi da je kanal zauzet, ne proverava svaki cas da li se oslobodio, vec proverava nakon nasumicno odabranog intervala
- **p-trajni CSMA** - ukoliko je kanal prazan emituje sa verovatnocom p, sa 1-p odustaje do sledeceg vremenskog intervala 

**CSMA/CD - CSMA with Collision Detection**

- smanjuje trosak kolizija tako sto ih detektuje i obustavlja slanje ostatka okvira
- interval u kom ce cvor sigurno cuti da se desila kolizija je 2D
=> resenje: ograniciti minimalnu velicinu okvira tako da traje najmanje 2D sekundi. tako cvor ne moze da zavrsi slanje pre nego sto shvati da se desila kolizija 

pitanje: sta ako drugi cvor salje?

**BEB - binarno exp odlaganje**

- prva kolizija - cekaj 0 ili 1 okvira
- opet kolizija - cekaj izmedju 0-3 okvira
- opet kolizija - cekaj izmedju 0-7 okvira
- veoma efikasan u praksi

## 22. MAC протоколи засновани на редоследу, Token Ring.

MAC protokoli zasnovani na redosledu predstavljaju uredjene protokole u kojima svaka stanica kada dodje na red moze da posalje okvir ili da propust redosled, ukoliko nema potrebu da salje.

Definise se uredjenje prema kojem cvorovi salju podatke. Kako definisati uredjenje?

**Token Ring:**

- organizujemo cvorove u prsten i prosledjujemo token u krug
- samo cvor sa tokenom moze da salje
- nema kolizija
- efikasnije pod opterecenjem
- uvek garantovan servis (nema izgladnjivanja)
- pakete uklanja stanica kojoj je namenjen paket ili koja je poslala paket

**mane:** 
- sta ako se izgubi token?
- visok dodatni trosak pri malom opterecenju

Uglavnom se primenjuju eksperimentalno, protokoli sa slucajnoscu se uglavnom mnogo bolje pokazuju


## 23. MAC protokoli za bezicne mreze

razlike u odnosu na zicane mreze:

- cvorovi mogu imati razlicite oblasti pokrivanja.
- cvorovi ne cuju dok salju
- bezicni signal se prima samo u blizini gde je veliki S/N ratio

**problem skrivenih cvorova:   A -> B <- C**

- cvorovi A i C su skriveni kada salju ka B
- ne mogu da se cuju medjusobno
- kolizija se detektuje tek na B

**problem izlozenih cvorova: A <- B  C -> D**

- B i C se nazivaju izlozeni cvorovi kad salju ka A i D
- ne zelimo da se cekaju, vec da salju u isto vreme

resenje: **MACA - Multiple Access with Collision Avoidance**

koristi se procedura rukovanja umesto CSMA

protokol:

- posiljalac emituje kratki okvir RTS sa informacijom o duzini (request to send)
- primalac prima RTS i emituje CTS (clear to send) sa kopiranom inf o duzini
- posiljalac prima CTS i zapocinje slanje, dok drugi okviri koji vide CTS a nisu slali RTS cekaju u skladu sa vremenom iz CTS
- ako je neko dobio RTS, a nije CTS zna da moze da salje
- kolizije i dalje moguce ali manje verovatne


## 24. Klasicni Eternet

- Najpopularniji vid organizovanja LAN tokom 80tih i 90tih
- 10MBps preko deljenog coax kabla
- koristi CSMA/CD sa BEB

forma okvira:
 
- **preambula** sluzi za sinhronizaciju primaoca sa posiljaocem 8B sekvenca 10101010, osim kod poslednjeg koji se zavrsava sa 11
- **adrese posiljaoca i primaoca** prvi bit 0- obicne adrese, 1-grupne adrese
- **tip** saopstava primaocu kom protokolu mreznog sloja treba proslediti okvir
- **podaci** mora biti najmanje 64 bajta zobog eventualnog naglog prekida i potencijalnih sukoba
- **kontrolni zbir** CRC32 za detekciju gresaka, nema ACK ili retransmisije

**Topologije:**

- **Linearna topologija** jedan kabal se provlaci kroz sve prostorije i sve stranice se prikljucuju u tackama racvanja
- **Topologija sa okosnicom** vertikalni vod od koga se preko specijalnih repetitora granaju horizontalni kablovi
- **Topologija stabla** najcesce se primenjuje
- **Segmentirana topologija** izmedju dva primopredajnika sme biti najvise cetiri repetitora, predstavlja niz kablovskih segmenata


## 25. Модерни (комутирани) Етернет.

Nema deljenog pristupa, vec se koriste switch-evi (kanali se razdvajaju na hardverskom nivou)

Cvorovi se povezuju na eternet fizickim vezivanjem parice na switch (vise kao topologija zvezde)

na fizickom nivou :  **hub** - ponavlja ulaz na sve izlaze (portove), ne zna za okvire


na nivou veze: **switch** - koristi adrese iz okvira kako bi prosledio na zeljeni izlaz, moguce vise istovremeno (port je obicno puni dupleks), potrebni su baferi

na mreznom: **ruter**

prednosti switcheva:

- prakticnije
- pouzdanije (ako otkaze jedna zica np)
- bolji protok (ne deli se)

okviri se prosledjuju na osnovu tabele relacija izmedju broja porta i adrese iz okvira. Da bi se popunila tabela, koristi se **ucenje unazad**. Radi lepo ako nema petlji

konacno resenje: pravi se razapinjuce stablo


## 26. Мрежни слој, улога, мотивација, рутирање и прослеђивање (укратко), типови сервиса на мрежном слоју, објашњења и њихов упоредни однос.

Zadatak mreznog sloja je da pakete sprovede celim putem od izvorista do odredista. Kontrolise saobracaj

Problemi sa switchevima:
 
- ne skaliraju se dobro
- inicijalno transmisija celom svetu- ne rade ako su tehnologije sloja veze razlicite
- ne omogucavaju kontrolu saobracaja

**Rutiranje** je proces odlucivanja u kom pravcu poslati podatke. Skupo, potreban distribuirani algoritam

**Prosledjivanje** je proces prosledjivanja podataka na osnovu lokalne tabele cvorova

Mrezni servisi:

- **datagramski model (paketi)**:
 
	- bez uspostave veze, poput poste
	- paket sadrzi adresu na osnovu koje se paket prosledjuje dalje
 	- svaki ruter ima svoju tabelu prosledjivanja, koja se menja tokom vremena
 	- za oznacavanje stanica se koriste IP adrese
 	- paketi sadrze i verziju, zaglavlje, duzinu paketa, kontrolni zbir

- **model virtuelnog kola** 
	- necemo za svaki paket da izmisljamo putanju, koristimo istu za svaku grupu
	- sa uspostavom veze, poput telefonije
 	- uspostavljanje kola
 	- prenos podataka
 	- brisanje kola
 	- paketi sadrze samo kratki id kola


Oba servisa koriste tehniku store-and-forward - ruteri dobijaju pakete koje cuvaju u baferima dok ih ne proslede dalje

Koristi se staticko multipleksiranje

ISP obicno koriste virtualna kola kako bi grupisali IP saobracaj


## 27. IP adrese i prefiksi

IPv4 (32b), IPv6 (128b)

IPv4: 4 8-bitna broja razdvojena tackama

**IP protokol** zadatak je da obezbedi prenos datagram od izvorista do odredista, bez obzira da li se racunari nalaze na istoj mrezi ili se druge mreze nalaze izmedju njih

**IP prefiksi:**

- adrese se grupisu u blokove koji se nazivaju prefiksi
- N-bitni prefiks je grupa adresa koje imaju isti prefiks duzine N
- N-bitni prefiks ima 2^32-N razlicitih adresa
- notacija oblika IPaddr/duzinapref
- vise i manje specificni prefiksi

**Javne IP adrese**

- jedinstvena oznaka na internetu
- mora se dodeliti pre upotrebe -IANA

**Privatne IP adrese**

- nisu globalno jedinstvene
- jedinstvene na nivou manjih mreza

dodeljivanje javnih ip adresa - IANA


## 28. IP prosledjivanje

sve IP adrese jedne mreze pripadaju istom prefiksu
svaki ruter poseduje tabelu parova (prefiks, cvor)
prefiksi u tabeli se mogu preklapati, koristi se pravilo najspecificnijeg

**Besklasno medjudomensko usmeravanje (CIDR)** 

- preostali prostor se podeli u blokove razlicite velicine ne vodeci racuna o klasama
- svaka ciljna adresa za usmeravanja se prosiruje se sa 32-bitnom maskom-prefiksom
- kad stigne paket izvlaci se IP adresa
- tabela se pregleda maskiranjem ciljne IP adrese i poredi sa ciljnim adresama u tabeli da bi se pronasla odgovarajuca
- ako se nadje vise odgovarajucih uzima se ona sa najduzim prefiksom


## 29. ARP и DHCP.

ARP  - odredjivanje adrese u sloju veze za ciljnu IP adresu
DHCP - dodeljivanje IP adrese racunaru u mrezi

**ARP (Address Resolution Protocol):**

- IP adrese se ne mogu koristiti za slanje paketa, jer hardver sloja veze podataka ne razume internet adrese, koriste se MAC adrese
- cvor koji zeli da sazna emituje ciljnu IP adresu
- cvor koji ima tu adresu kao izvornu, vraca odgovor sa svojom adresom u sloju veze
- cuva rezultat, ako treba opet da stupi u vezu sa istim racunarom

**DHCP:**

Javalja se problem dodljivanja IP adresa. Ethernet adresa se zadaje fabricki, IP ne

*stari pristup:* rucno podesavanje IP adrese uredjaja. 

*novi pristup:* **DHCP (Dynamic Host Configuration Protocol)**

- cvor emituje paket celoj mrezi na spec adresi za emitovanje (255.255.255.255), jer ne zna gde je DHCP (DISCOVER)
- DHCP odgovara ciljnom cvoru na osnovu njegove MAC adrese sa predlozenom IP adresom (OFFER)
- cvor emituje odgovor da mu odgovara IP adresa (moze biti vise DHCP) (REQUEST)
- DHCP potvrdjuje i brise adresu iz spiska slobodnih adresa (ACK)
klijent moze i da obnovi IP adresu koju je imao ranije (salje se samo REQUEST i vraca ACK)
- omogucava paralelan rad sa vise repliciranih DHCP servera
- IP adresa se iznajmljuje tj. dodeljuje na odredjeni vremenski period



## 30. ICMP i NAT.

**ICMP - Internet Control Message Protocol **

- Sta ako se desi greska prilikom prosledjivanja? potrebno je javiti senderu
- Kada ruter detektuje gresku, salje ICMP paket posiljaocu
- ICMP paket je isti kao IP paket samo sto ima tip i kod greske, kontrolni zbir

**NAT - Network Address Translation**

*motivacija:* nestasica IP adresa

*ideja:* 

- racunari koriste privatne IP adrese, koje NAT povezuje na jednu javnu dodeljenu od strane ISP
- NAT odrzava tabelu preslikavanja unutrasnjih u spoljne adrese pomocu portova (portovi su neophodni da bi bilo 1-1 preslikavanje)
- prilikom slanja podatka iz lokalne mreze, paketu se menja adresa posiljaoca u skladu sa zadatim preslikavanjem
- prilikom prihvatanja se menja adresa primaoca u skladu sa zadatim preslikavanjem

*problem:* narusena je cistoca slojevitosti - radi na mreznom sloju a barata portovima*

*prednosti:*

- smanjuje potrebe za javnim IP adresama
- lako se instalira
- cesto u sebi ima i neki vid zastite
- pomaze po pitanju privatnosti

*mane:*

- narusena je cistoca slojevitosti
- paketi mogu da se primaju samo ako je prethodno bilo poslatih paketa
- tesko je koristiti servere preko NAT-a


## 31. Рутирање, механизми алокације протока, модели испоруке, циљеви рутирања, принципи дизајна алгоритама рутирања, рутирање са најкраћим путевима (најмањим трошком), Дијкстрин алгоритам.

Rutiranje je odredjivanje putanja kojima ce se vrsiti prosledjivanje.

Kljucni aspekt rutiranja je alokacija protoka

**Mehanizmi alokacije protoka:**

- rutiranje osetljivo na opterecenje - sekunde/ kriticni cvorovi opterecenja
- rutiranje - minuti/ otkazi cvorova
- oblikovanje protoka sati/opterecenje mreze
- rezervacija protoka meseci/korisnici mreze

Postoje razliciti algoritmi rutiranja za razlicite modele isporuke:
unicast, broadcast, multicast, anycast

Ciljevi rutiranja: 
tacnost, efikasnost, ravnopravnost, brza konvergencija, skalabilnost 

Principi dizajna algoritama rutiranja:

- decentralizovani i distribuirani
- cvorovi su ruteri
- svi cvorovi su ravnopravni
- cvorovi saznaju ukupno stanje mreze tako sto razmenjuju poruke sa susedima
- cvorovi rade konkurentno
- mogu se desiti otkazi cvorova

**Rutiranje sa najmanjim troskom:**

prvo se mora definisati trosak - kasnjenje, novac, protok, br hopova...
pp da je graf neusmeren i da ima simetricne troskove

**Dijkstrin algoritam:**

racuna najkrace puteve od zadatog cvora do svih ostalih. Rezultat je drvo

Princip optimalnosti: segmenti optimalnih puteva su takodje najkraci putevi

- postaviti sve cvorove kao privremene
- rast do svih cvorova je inicijalno inf
- dok ima privremenih cvorova:
  - uzmi privremeni cvor X koji ima najmanju udaljenost od zadatog cvora
  - izbaci X iz skupa privremenih i dodaj vezu ka njemu u drvo
  - umanji udaljenosti suseda u skladu sa novododatom udaljenoscu


## 32. Рутирање засновано на вектору раздаљине.

ideja se zasniva na razmeni vektora (tabela) razdaljine izmedju susednih cvorova
retko se sada koristi, pre koristio arpanet

svaki cvor radi sledece:

- inicijalizuje udaljenost do samog sebe na 0, a do ostalih na inf
- periodicno salje svoj vektor susedima
- updatuje svoj vektor na osnovu vektora dobijenih od suseda

ako se ukloni cvor susedi ne obavljaju razmene s njim pa s vremenom zaborave na njega

ozbiljan problem razbijanje mreze na dva dela - brojanje do inf


## 33. Плављење.

Algoritam statickog usmeravanja, emitovanje poruke svim cvorovima

**pravilo:** kad stigne poruka prosledi je svim susedima ali zapamti kako se opet ne bi prosledjivala ako stigne opet

neefikasno

dovoljno je zapamtiti izvor i redni broj poruke. Sledeca poruka se prihvata ako ima veci redni broj

moze se omoguciti i ARQ


## 34. Рутирање засновано на стању веза.

**Link-State Routing - dve faze:**

- cvorovi plave mrezu informacijama o svojoj lokalnoj topologiji (LS packet)
- svaki cvor racuna svoju tabelu prosledjivanja (npr Dijkstra)

ako se desi promena u lokalu, cvor plavi opet sa novim LSP
ukoliko se dese otkazi, isto sve


## 35. Вишециљно рутирање са најкраћим путевима (ECMP).

Dozvoljavamo visestruke puteve, odnosno vise nemamo drvo koje formiraju najkraci putevi od zadatog cvora, nego usmereni aciklicki graf

Zadrzavamo sve najbolje puteve, a ne samo jedan. Koristi se Dijkstra

*ideja:* dozvoljavanje vise puteva - redundantnost++, pouzdanost++
u tabeli nema npr A -> E , vec A -> E, F, G ..

razlika: ne formira se drvo, vec DAG (usmereni aciklicki graf)

pitanje je na koji da se prosledi od mogucih?

- random : opterecenje--, kasnjenje++?
- *kontrolisan nasumicno* fiksirati na osnovu izvora i cilja



## 36. Хијерархијско рутирање.

- ideja je da se rutiranje ne vrsi na zasebnim cvorovima jer se ne skalira dobro
- cvorovi se grupisu u regione, potom unutar regiona vrsimo specificnije rutiranje
- putanja se dobija tako sto se rutira paket u najmanjem regionu (npr ISP), onda npr na nivou drzave, i zatim opet na ciljni ISP itd
- nije optimalno ali efikasnije
- ovde dolazi IP prefiksi u igru, svaki region moze imati isti IP prefiks


## 37. Транспортни слој, улога, типови сервиса и њихово поређење.

nadogradnja mreznog sloja koja omogucava prenos podataka sa zeljenim stepenom pouzdanosti i kvaliteta

moze da evidentira izgubljene ili ostecene pakete i da ih salje ponovo

omogucava komunikaciju izmedju dva krajnja korisnika

jedinica informacije na transportnom sloju se naziva segment, koji se ugradjuje u pakete, koji se ugradjuju u okvire

tipovi servisa:

	       TCP         |      UDP
	-----------------------------------
	ostvarivanje veze  |   datagrami
	 isporuka jednom   | poruke se mogu slati vise puta, i zagubiti
	proizvoljna duzina | ogranicena duzina
	pril. kontrola toka| salje se bez obzira na stanje primaoca
	pril. kont. opter. | salje se bez obzira na stanje mreze



## 38. Socket API, пример једноставног клијент-сервера (псеудокод), портови.

**Socket API** apstrakcija za upotrebu mreznih usluga

- podrzava i tokove i datagrame
- soketi omogucavaju procesima da se povezuju na mrezu putem razlicitih portova

funkcije: socket, bind, listen, accept, connect, send, receive, close

server:

	s = socket();
	bind(s, 10000);
	listen(s);
	while true
	  connection = s.accept();
	  // procitaj ili upisi u soket, stagod
	  connection.close()

client:

	s = new socket("hostname", 10000);
	s.connect();
	s.send("aaa");
	s.close();

- procesi se identifikuju trojkom (IPaddr, protokol, port)
- portovi su 16bitni celi brojevi
- preodredjeni portovi za neke protokole (20,21 - FTP, 22 - SSH)


## 39. UDP

UDP protokol ne upravlja tokom, ne kontrolise greske i ne salje ponovo pogresno primljene segmente. Sve to prepusta korisnickim procesima. Predstavlja interfejs ka IP protokolu i dodatno demultipleksira procese koji koriste isti prikljucak.

Koristi UDP bafere koji zadrzavaju pakete koji stizu za razlicite portove

Koriste ga programi gde pouzdanost nije preterano bitna: voip, DNS, DHCP...

zaglavlje:

izvorisni prikljucak(port), odredisni prikljucak, duzina UDP paketa, kontrolni zbir(opciono)


## 40. Успостава и прекид везе на транспортном слоју (уопштено).

krajnji cvorovi moraju biti svesni uspostave veze pre bilo kog slanja/primanja

uspostava veze podrazumeva:

- podesavanje stanja krajnjih cvorova
- posto se koriste klizni prozori, strane treba da usaglase pocetne brojeve segmenata
- segmenti se ponovo salju ako se izgube

koristi se trofazno rukovanje

- klijent salje segment SYN(seq = x) gde je x pocetni broj segmenta
- server odgovara tako sto salje sledeci broj koji ocekuje i svoj pocetni broj SYN(seq = y, ack = x+1)
- klijent potvrdjuje broj ack = y+1, seq = x+1

obe strane treba da prekinu vezu, dva koraka:

- aktivna strana salje FIN(x), pasivni potvrdjuje sa ACK(x+1)
- pasivni salje FIN(y), aktivni potvrdjuje sa ACK(y+1)
- svako gasi svoju stranu posle slanja fin i dobijanja ack za isti


## 41. Протоколи клизних прозора на транспортном слоју.

za razliku od prethodnih, ovde se prica o povezivanju cvorova na internetu (krajnje tacke)

postoji dosta varijacija protokola u zavisnosti od baferisanja, potvrde poruka i retransmisija: vrati se n, selektivno ponavljanje

zajednicko za sve:

- od aplikativnog sloja dobijaju segmente po redu
- aplikativnom sloju salju segmente po redu

**posiljalac:**

- baferise najvise N segmenata dok ne stigne potvrda za njih
- LFS: poslednji poslat segment, LAR: poslednji potvrdjeni segment (pre njega su svi potvrdjeni)
- salje dok god je LFS - LAR <= N

**Primalac:**

**vrati se n:**

- primalac ima bafer velicine 1 i cuva vrednost poslednjeg segmenta prosledjenog aplikativnom sloju (LAS)
- nakon primanja segmenta, ako je redni broj LAS+1:
  prihvati, prosledi aplikativnom, LAS++, posalji ACK
- inace odbij

**selektivno ponavljanje (TCP koristi ovo):**

- primalac ima bafer velicine N
- odrzava stanje promenljive LAS
- prihvata segment ako je iz opsega [LAS+1, LAS+N] i pritom:
  baferise ako je stigao segment sa brojem LAS+1, salje bafer aplikativnom sloju i azurira LAS, salje potvrdu

**retransmisije:**

**vrati se n:** ima tajmer koji kada istekne, ponovo salje sve segmente od LAR+1

**selektivno:** ima tajmer za svaki nepotvrdjeni segment


## 42. Контрола тока података на транспортном слоју.

Sta ako primalac sporo prima podatke? Treba usaglasiti brzinu slanja

Primalac ima bafer velicine W, ako popuni bafer, a aplikativni sloj ne moze da primi podatke, mora da odbaci sve naredne segmente.

*Resenje* kada primalac salje potvrdu da je dobio segment salji i broj slobodnih mesta u baferu - WIN. Posljlac salje maksimalno WIN segmenata


## 43. Retransmisjia i prilagodljive pauze (tajmauti) na transportnom sloju

Bitna stvar za TCP protokol.

Pauza mora da bude dobro procenjena
	
- prevelike usporavaju kretanje prozora
- prekratke izazivaju sumnjivu retransmisiju

Lako se odredjuje za LAN

Tesko se odredjuje za internet (sirok opseg, promenljiv RTT)

Ideja je da se odredi kratkorocni RTT i njegova varijansa

Formula zasnovana na pomerajucim procesima:

- SRTT(n+1) = 0.9*SRTT(n) + 0.1*RTT(n+1)
- Svar(n+1) = 0.9*Svar(n) + 0.1*|RTT(n+1) - SRTT(n+1)|

TCP Timeout(n) = SRTT(n) + 4*Svar(n)

Sto je veca varijansa manje smo sigurni pa je i gornja granica vise udaljena


## 44. TCP, svojstva zaglavljivanje, realizacija kliznih prozora, uspostava i prekid veze (specificno)

**TCP svojstva:**

- pouzdan tok bajtova - aplikativnom segmente salje ispravne i po redu
- zasnovan na vezama
- klizni prozori zarad pouzdanosti sa prilagodljivim pauzama
- kontrola toka za spore primaoce

**TCP zaglavlje**

- **prtovi** - indetifikuju programe
- **redni broj sekvence i acknowledgment number (SEQ/ACK)** - koriste se u okviru protokola kliznih prozora
- **velicina prozora**
- **kontrola gresaka**

**Klizni prozori**

Primalac:

- kumulativni ACK govori koji je sledeci ocekivani bajt(LAS+1)
- selektivni ACK-ovi opciono zarad optimizacije, listanje do tri opsega primljenih bajtova

Posiljalac:

- koristi prilagodljivu pauzu za retransmisju segmenata koji pocinju od LAS+1
- koristi heuristiku kako bi brze zakljucio koji segment su igubljeni i time izbegao istek pauze
- heuristika: tri duplikata ACK-a implicirju gubitak

**Uspostava veze**

Veze u TCP protokolu se uspostavljaju sa mehanizmom trostepenog usaglasavanja

Server LISTEN i posle ACCEPT
Klijen CONNECT(salje IP adresu prikljucak, velicinu segmenta koji moze da primi..)


**Raskidanje veze**

Isto ja hocu pa ti potvrdi i ti kazes ja hocu pa ja potvrdim


## 45. Zagusenje na transportnom sloju, opis problema i mehanizam za resavanje AIMD

**Zagusenje** ako je ulazni saobrcaj veci od izlaznog saobracaja (na ruteru , swich-u)

Perfomanse se drasticno smanjuju kako se povecava zagusenje

**Alokacija prostora**

- Bitan zadatak u resavanju problema zagusenja je dodeljivanje kapaciteta posiljaocima
- dodela treba da bude efikasna i ravnopravna
- efikasnost skoro ceo kapacitet je upotrebljen
- ravnopravnost svaki posiljalac dobija udeo protoka

Mrezni sloj detektuje zagusenje, Transportni sloj ga izaziva

**Okvirna ideja** posiljaoci pilagodjavaju svoj odlazni saobracaj na osnovu onoga sto detektuju iz mreze.

**AIMD (Additive Increse Multiplicative Decrease)** kontolni mehanizam koji omogucava dostizanje dobre alokacije

- Posiljaoci aditivno povecavaju brzinu slanja podataka dok mreza ne postane zagusena
- Nakon toga je umnozeno smanjuju kada uoce zagusenje
- TCP koristi ovo u nekoj formi


## 46. Апликативни слој, улога, интеракција са слојем испод, преглед Интернет апликација.

poruke aplikativnog sloja se dele na segmente, a oni dalje obicno pripadaju jedinstvenom paketu

u zavisnosti od toga sta aplikacijama treba, koriste se TCP (web) ili UDP (dns, skype)

protokoli aplikativnog sloja su cesto deo aplikacije

telnet, ftp, ssh, smtp, http, p2p...


## 47. DNS, улога, ранији приступ, модерни приступ, TLD, слогови.

domen umesto ip adrese jer je lakse za ljude

ne zelimo da tablicu domena i ip adresa cuvamo na jednom racunaru

imena su identifikatori resursa, adrese su lokatori resursa a odredjivanje adrese je preslikavanje imena u adresu

pre dns je postojao hosts.txt (u arpanet) preuzimanje te datoteke svaki dan sa centralnog cvora, imena razdvojena tackama, po nivoima hijerarhije: lcs.mit.edu

**DNS:**

- sistem koji vrsi preslikavanje imena u IP adresu
- lak za upravljanje, efikasan
- distribuirana tabela, hijerarhijska organizacija


**TDL (Top Level Domains)**
	
- odrzva organizacija ICANN
- inicijalni 6 .com .edu .gov .mil .org .net 
- kasnije dodati i .aero .museum .xxx
- oko 250 nacionalnih TLD


**SLogovi**

- svakom domenu se moze pridruziti zapis resursa
- kad razresivac DNS serveru preda ime domena od njega dobije zapis resursa
- zapis resursa je sastavljen od 5 dubleta
	- ime_domena
	- zivotni_vek
	- klasa (IN)
	- tip 
	- znacenje


## 48. DNS, зоне, опис механизма одређивања адреса.

- zona je neprekidno parce prostora imena
- zone su osnov za dalju distribuciju
- svaka zona ima nadlezan server imena
- svaka zona sadrzi podesavanja (slogove) koji pruzaju:
	- informacije o imenovanim racunarima
	- informacije vezane za slanje poste
	- informacije o parametrima

lokalni dns - najblizi dns server klijentu (ISP, ali postoje i javni)

**rekurzivni DNS:**
zavrsava ceo posao za klijenta, lokalni dns isporucuje klijentu adresu

**iterativni DNS:**
ako ne zna za ime, lokalni vraca adrese servera koji znaju

**kasnjenje:**

- treba da bude malo, da bi se brzo ucitavale strane
- ako se kesira ime u dns serveru on moze momentalno da odgovori
- informacije o delu imena se mogu iskoristiti

**Lokalni DNS**

- u vlasnistvu firme ili ISP
- postoje i javni Google DNS
- klijent mora da zna koji mu je DNS, podesava se pomocu DHCP kad dobija IP adresu


**Koreni DNS "."**

- cini zapravo 13 servera na preko 250 repliciranih masina
- njihove IP su fiksirane u podesavanjima drugih DNS serera

dns poruke koriste port 53, ARQ, 16bit ID poruke


## 49. HTTP протокол, преузимање Веб документа.

- osnovni protokol za preuzimanje www dokumenata
- http protokol koristi TCP, obicno port 80
- stari 1.0 HTTP salje se i dobija samo jedan odgovor
- 1.1 HTTP podrzava trajne veze

**preuzimanje dokumenta:**

- korisnik kuca adresu
- odredjuje se ip adresa
- uspostavlja se tcp veza sa serverom
- salje se http zahtev za konkretan dokument sa servera
- ceka se http odgovor
- vrsi se preuzimanje
- zatvaranje veze

**komande pri pravljenju zahteva:**
get, head, post, put, delete, trace, connect, options

**kroz odgovor se vracaju kodovi :**

1xx informacija
2xx uspeh
3xx preusmeravanje
4xx greska klijenta
5xx greska servera


## 50. HTTP performanse

**PLT - page load time**, zavisi od mnogo faktora:

- strukture dokumenta
- verzije http i tcp protokola
- mreznog protoka i rtt

http/1.0 koristio 1 tcp vezu da preuzme jedan dokument - ogroman PLT

kako smanjiti PLT?

- kompresija poslatog sadrzaja
- prilagodjavanje http da bolje koristi protok
- izbegavanje ponovljenih http zahteva (cache, proxies)
- pomeranje zahteva blize korisniku (CDN)
- paralelne TCP veze (pregledac npr radi sa 8 http konteksta)
- trajne veze


## 51. HTTP кеширање и HTTP проксији.

omogucavaju visestruke upotrebe istog sadrzaja

**cache** - cuva se lokalna kopija stranice 

- klijent salje serveru uslovni GET
- ako je lokalna kopija zastarela server salje novu stranicu


**kesiranje unapred** 

- kad proksi preuzme stranu od servera dohvati i povezane strane za svaki slucaj
- Last-Modifed i If-Modified kaze i kad je poslednji put menjanjo pa znam koliko da cuvam

**http proxies:**

- posrednici izmedju grupe klijenta i servera 
- kesira se sadrzaj za grupu
- mogu se u proxy ugraditi i sigurnosni mehanizmi (cenzura npr)


## 52. CDN(Content distributivne mreze).

CDN arhitektura u kojoj provajder postavlja distribuiranu kolekciju masina na lokacijama unutar interneta i koristi ih za prikazivanje sadrzaja klijentima

efikasna isporuka cesto iskoriscenog sadrzaja, smanjuje cekanje, potrosnju ukupnog protoka

postavljanje sadrzaja blize klijentima

moze da bude geografski ciljano, koristi se DNS


## 53. P2P.

Ne moze uvek da se postavi CDN

Osnovna ideja P2P deljenje datoteka je da mnogi racunari udruze svoje resurse i formiraju sistem za ramenu sadrzaja

Nema centralnih cvorova - svako je i klijent i server i svi su ravnopravni

Svaki cvor mora da nauci gde se nalazi sadrzaj - koriste se DHT(distribuirane hes tabele). Indeks je distribuiran preko svih cvorova, daje spisak svih cvorova koji sadrze trazeni sadrzaj

**Tracker serveri** racunari cija je namena da pamte spiskove cvorova koji poseduju odredjenu datoteku
 


Kako radi BitTorrent:

- zapocinje torrent datotekom. U njoj se nalazi lokacija Tracker servera ili kako da kontaktiramo DHT
- razmena podataka se vrsi sa razlicitim cvorovima. Trgovina
- Sto vise saljem vise i dobijam
- Cvorovi koji imaju sadrzaj ili zele da ga preuzmu se povezu i zapocinju razmene
- Delovi koji se salju su nasumicne izabrani
- Pijavica ako cvor samo uzima podatke, vremenom ga izbacimo






