/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 7: El-gamal-Signatur                              *
 **                                                           *
 **************************************************************
 **
 ** getreport.c: Rahmenprogramm für den Signatur-Versuch
 **/

#include "sign.h"
#include <time.h>
#include <gmp.h>

static mpz_t p;
static mpz_t w;

const char *factorlist_hex[] = {
	"5", "7", "9", "B", "D", "11","13","17","1D","1F","25","29",
	"2B","2F","35","3B","3D","40","43","47","49","4F","53","59",
	"61","65","67","6B","6D","71","7F","83","89","8B","95","97",
	"9D","A3","A7","AD","B3","B5","BF","C1","C5","C7","D3","DF",
	"E3","E5","E9","EF","F1","FB","101","107","10D","10F","115",
	"119","11B","125","133","137","139","13D","14B",
	"10000000F", "12000050F", 0
};

int nfactors;
int debug = 0;
mpz_t *factorlist;              /* Zugriff hierauf wie auf Array. Index 0<=i<nfactors */

/*
 * init_factors() : Füllt die interne factorlist mit Faktoren.
 */
static void init_factors(void)
{
	int i;
	mpz_t tmp;

	for (nfactors=0; factorlist_hex[nfactors]; nfactors++);
	factorlist = calloc(nfactors, sizeof(mpz_t));
	mpz_init(tmp);
	mpz_set_ui(tmp, 1);
	for (i = 0; i < nfactors; i++) {
		mpz_init(factorlist[i]);
		mpz_set_str(factorlist[i], factorlist_hex[i], 16);
		mpz_mul(tmp, tmp, factorlist[i]);
	}
	mpz_add_ui(tmp, tmp, 1);
	if (mpz_cmp(tmp, p)) {
		printf ("FATAL: Faktoren stammen nicht von p-1!\n");
		exit (1);
	}
	mpz_clear(tmp);
}

/*
 * babyStepGiantStep(mpz_t x_i, mpz_t a_i, mpz_t w_i, mpz_t p_i):
 *
 * Berechnet x_i so dass a_i = w_i ^ x_i mod p.
 */
static void babyStepGiantStep(mpz_t x_i, mpz_t a_i, mpz_t w_i, mpz_t p_i)
{
	/*>>>>                                                <<<<*
	 *>>>> AUFGABE: Implementierung von BabyStepGiantStep <<<<*
	 *>>>>                                                <<<<*/
}

/*
 * dlogP(x, y):
 *
 * Berechnet x, wobei y = w ^ x mod p mithilfe der Faktorisierung von p - 1.
 */
static void dlogP(mpz_t x, mpz_t y)
{
	init_factors();
	/*>>>>                                            <<<<*
	 *>>>> AUFGABE: Berechnen des geheimen Schlüssels <<<<*
	 *>>>>                                            <<<<*/
}


/*
 * Verify_Sign(mdc,r,s,y) :
 *
 *  überprüft die El-Gamal-Signatur R/S zur MDC. Y ist der öffentliche
 *  Schlüssel des Absenders der Nachricht
 *
 * RETURN-Code: 1, wenn Signatur OK, 0 sonst.
 */
static int Verify_Sign(mpz_t mdc, mpz_t r, mpz_t s, mpz_t y)
{
	/*>>>>                                               <<<<*
	 *>>>> AUFGABE: Verifizieren einer El-Gamal-Signatur <<<<*
	 *>>>>                                               <<<<*/
	if (debug)
		gmp_printf("Verifying Signature for: \nm=%Zd, (r, s)=(%Zd, %Zd), pk=%Zd.\n", mdc, r, s, y);
	
	mpz_t a, b, c, d, e;

	// a = y_A ^ r mod p
	mpz_init(a);
	mpz_powm(a, y, r, p);
	if (debug)
		gmp_printf("y_A^r mod p : %Zd ^ %Zd mod %Zd = %Zd.\n", y, r, p, a);


	// b = r ^ s mod p
	mpz_init(b);
	mpz_powm(b, r, s, p);
	if (debug)
		gmp_printf("r^s mod p : %Zd ^ %Zd mod %Zd = %Zd.\n", r, s, p, b);

	// c = (y_A ^ r mod p) * (r ^ s mod p)
	mpz_init(c);
	mpz_mul(c, a, b);
	if (debug) 
		gmp_printf("a * b = c : %Zd * %Zd = %Zd.\nc mod p : %Zd mod", a, b, c, c);

	// d = (y_A ^ r mod p) * (r ^ s mod p) mod p
	mpz_init(d);
	mpz_mod(d, c, p);
	if (debug)
		gmp_printf(" %Zd = %Zd.\n", p, d);

	// e = w ^ m mod p
	mpz_init(e);
	mpz_powm(e, w, mdc, p);
	if (debug)
		gmp_printf("w^m mod p : %Zd ^ %Zd mod %Zd = %Zd.\n", w, mdc, p, e);

	if (mpz_get_ui(d) == mpz_get_ui(e)) {
		if (debug)
			gmp_printf("m=%Zd and sign(r,s)=(%Zd,%Zd) verified.\n\n", mdc, r, s);
		return 1;
	}

	if (debug)
		gmp_printf("m=%Zd and sign(r,s)=(%Zd,%Zd) not verified.\n\n", mdc, r, s);

	mpz_clears(a, b, c, d, e, NULL);
		
	return 0;
}


/*
 * Generate_Sign(m,r,s,x) : Erzeugt zu der MDC M eine El-Gamal-Signatur 
 *    in R und S. X ist der private Schlüssel
 */
static void Generate_Sign(mpz_t mdc, mpz_t r, mpz_t s, mpz_t x)
{
	/*>>>>                                           <<<<*
	 *>>>> AUFGABE: Erzeugen einer El-Gamal-Signatur <<<<*
	 *>>>>                                           <<<<*/

	if (debug) {
		gmp_printf("Generating Signature for: \np=%Zd, g=%Zd, m=%Zd, sk=%Zd.\n", p, w, mdc, x);
	}

	mpz_t k, gcd, p_1, k_1;
	gmp_randstate_t gmpRandState; 

	mpz_init(gcd);
	mpz_set_ui(gcd, 0);
	mpz_init(p_1);
	mpz_sub_ui(p_1, p, 1);
	mpz_init(k);
	mpz_init(k_1);

	// lets random some
	gmp_randinit_default(gmpRandState);
	gmp_randseed_ui(gmpRandState, time(NULL));
	
	// A zieht eine Zufallszahl k mit k < p-1 und ggT(k, p-1) = 1
	while(mpz_get_ui(gcd) != 1) {
		mpz_set_ui(gcd, 0);
		mpz_urandomm(k, gmpRandState, p_1);
		mpz_gcd(gcd, k, p_1);
	}
	if (debug)
		gmp_printf("Found a k=%Zd\n", k);

	//mpz_set_ui(k, 213); // Für Beispiel: 13, 213, 137

	// und berechnet r := w^k mod p
	mpz_powm(r, w, k, p);
	if (debug)
		gmp_printf("r = w^k mod p : r = %Zd ^ %Zd mod %Zd = %Zd.\n", w, k, p, r);

	// invert k mod (p-1) => k_1
	mpz_invert(k_1, k, p_1);
	if (debug)
		gmp_printf("k * k^(-1) = 1 mod (p-1) : %Zd * %Zd = 1 mod %Zd.\n", k, k_1, p_1);

	// und s := (m - r*x_A) * k^(-1) mod (p-1)
	mpz_t tmp;
	mpz_init(tmp);
	mpz_mul(tmp, r, x);
	mpz_sub(s, mdc, tmp);
	mpz_mul(s, s, k_1);
	mpz_mod(s, s, p_1);

	if (debug)
		gmp_printf("s = (m - r*sk) * k^(-1) mod (p-1) : s = (%Zd - %Zd*%Zd) * %Zd mod (%Zd) = %Zd.\n", mdc, r, x, k_1, p_1, s);

	if (debug)
		gmp_printf("r=%Zd, s=%Zd.\n\n", r, s);

	mpz_clears(k, gcd, p_1, k_1, tmp, NULL);
	gmp_randclear(gmpRandState);


}

int main(int argc, char **argv)
{
	Connection con;
	int cnt,ok;
	Message msg;
	mpz_t x, Daemon_y, Daemon_x, mdc, sign_s, sign_r;
	char *OurName;

	mpz_init(x);
	mpz_init(Daemon_y);
	mpz_init(Daemon_x);
	mpz_init(mdc);
	mpz_init(sign_s);
	mpz_init(sign_r);
	mpz_init(p);
	mpz_init(w);

	/**************  Laden der öffentlichen und privaten Daten  ***************/
	if (!Get_Private_Key(NULL, p, w, x) || !Get_Public_Key(DAEMON_NAME, Daemon_y)) exit(0);


	/********************  Verbindung zum Dämon aufbauen  *********************/
	OurName = "manton";// MakeNetName(NULL); /* gibt in Wirklichkeit Unix-Gruppenname zurück! */
	if (!(con=ConnectTo(OurName,DAEMON_NAME))) {
		fprintf(stderr,"Kann keine Verbindung zum Daemon aufbauen: %s\n",NET_ErrorText());
		exit(20);
	}


	/***********  Message vom Typ ReportRequest initialisieren  ***************/
	msg.typ  = ReportRequest;                       /* Typ setzten */
	strcpy(msg.body.ReportRequest.Name,OurName);    /* Gruppennamen eintragen */
	Generate_MDC(&msg, p, mdc);                     /* MDC generieren ... */
	Generate_Sign(mdc, sign_r, sign_s, x);          /* ... und Nachricht unterschreiben */
	strcpy(msg.sign_r, mpz_get_str(NULL, 16, sign_r));
	strcpy(msg.sign_s, mpz_get_str(NULL, 16, sign_s));

	/*************  Machricht abschicken, Antwort einlesen  *******************/
	if (Transmit(con,&msg,sizeof(msg))!=sizeof(msg)) {
		fprintf(stderr,"Fehler beim Senden des 'ReportRequest': %s\n",NET_ErrorText());
		exit(20);
	}

	if (Receive(con,&msg,sizeof(msg))!=sizeof(msg)) {
		fprintf(stderr,"Fehler beim Empfang des 'ReportResponse': %s\n",NET_ErrorText());
		exit(20);
	}


	/******************  Überprüfen der Dämon-Signatur  ***********************/
	printf("Nachricht vom Dämon:\n");
	for (cnt=0; cnt<msg.body.ReportResponse.NumLines; cnt++) {
		printf("\t%s\n",msg.body.ReportResponse.Report[cnt]);
	}

	Generate_MDC(&msg, p, mdc);
	mpz_set_str(sign_r, msg.sign_r, 16);
	mpz_set_str(sign_s, msg.sign_s, 16);
	ok=Verify_Sign(mdc, sign_r, sign_s, Daemon_y);
	if (ok) printf("Dämon-Signatur ist ok!\n");
	else printf("Dämon-Signatur ist FEHLERHAFT!\n");

	/*>>>>                                      <<<<*
	 *>>>> AUFGABE: Fälschen der Dämon-Signatur <<<<*
	 *>>>>                                      <<<<*/

	mpz_clears(x, Daemon_y, Daemon_x, mdc, sign_s, sign_r, p, w, NULL);

	return 0;
}

int mainTest(int argc, char **argv) 
{
	mpz_t mdc, r, s, sk, pk;

	mpz_init(mdc);
	mpz_set_ui(mdc, 168); // 10, 100, 168
	mpz_init(r);
	mpz_set_ui(r, 0);
	mpz_init(s);
	mpz_set_ui(s, 0);
	mpz_init(sk);
	mpz_set_ui(sk, 66); // 11, 127, 66
	mpz_init(pk);
	mpz_set_ui(pk, 1452); // 7, 132, 1452
	
	mpz_init(p);
	mpz_set_ui(p, 4679); // 17, 467, 4679
	mpz_init(w);
	mpz_set_ui(w, 807); // 3, 2, 807

	Generate_Sign(mdc, r, s, sk); // (12, 14), (29, 51)

	Verify_Sign(mdc, r, s, pk);

	mpz_clears(mdc, r, s, sk, pk, NULL);

	return 0;
}
