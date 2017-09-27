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
int debug = 1;
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
	Computes the greatest common devisor of a and b and saves it in gcd.
*/
static void Get_GCD(mpz_t gcd, mpz_t a, mpz_t b) {
	int i;
	for (i = 1; i <= mpz_get_ui(a) && mpz_get_ui(b); ++i) {
		if (mpz_get_ui(a)%i==0 && mpz_get_ui(b)%i==0)
			mpz_set_ui(gcd, i);
	}
	if (debug) 
		printf("gcd(%d, %d) = %d.\n", mpz_get_ui(a), mpz_get_ui(b), mpz_get_ui(gcd));
}

/*
	The extended euclidean algorithm computes a number c so that a * c [=] 1 mod b
	Prerequisite: gcd(a, c) = 1
*/
static int Get_Inverse(int a, int b) {

	int x[3], y[3];
	int quotient = a / b;
	int remain = a % b;

	x[0] = 0;
	y[0] = 1;
	x[1] = 1;
	y[1] = quotient * (-1);

	int i;
	for (i = 2; (b % (a%b)) != 0; i++) {
		a = b;
		b = remain;
		quotient = a / b;
		remain = a % b;
		x[i%3] = (quotient * (-1) * x[(i-1)%3]) + x[(i-2)%3];
		y[i%3] = (quotient * (-1) * y[(i-1)%3]) + y[(i-2)%3];
	}
	return x[(i-1)%3];
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
	mpz_t a, b, c, d;

	// y_A ^ r mod p
	mpz_init(a);
	mpz_powm(a, y, r, p);
	if (debug)
		printf("y_A^r : %d ^ %d = %d.\n", mpz_get_ui(y), mpz_get_ui(r), mpz_get_ui(a));

	// r ^ s mod p
	mpz_init(b);
	mpz_powm(b, r, s, p);
	// printf("r^s : %d ^ %d = %d.\n", mpz_get_ui(r), mpz_get_ui(s), mpz_get_ui(b));

	// w ^ m mod p
	mpz_init(c);
	mpz_powm(c, w, mdc, p);
	if (debug)
		printf("w^m : %d ^ %d = %d.\n", mpz_get_ui(w), mpz_get_ui(mdc), mpz_get_ui(c));

	// (y_A ^ r mod p) * (r ^ s mod p)
	mpz_init(d);
	mpz_mul(d, a, b);
	if (debug)
		printf("a * b = d : %d * %d = %d.\n", mpz_get_ui(a), mpz_get_ui(b), mpz_get_ui(d));

	// (y_A ^ r mod p) * (r ^ s mod p) mod p
	mpz_mod(d, d, p);
	if (debug)
		printf("d mod p = %d.\n", mpz_get_ui(d));

	if (mpz_get_ui(c) == mpz_get_ui(d)) {
		if (debug)
			printf("m=%d and sign(r,s)=(%d,%d) verified.\n", mpz_get_ui(mdc), mpz_get_ui(r), mpz_get_ui(s));
		return 1;
	}

	if (debug)
		printf("m=%d and sign(r,s)=(%d,%d) not verified.\n", mpz_get_ui(mdc), mpz_get_ui(r), mpz_get_ui(s));
		
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

	mpz_t k, gcd, p_1, k_1;
	mpz_init(gcd);
	mpz_set_ui(gcd, 0);
	mpz_init(p_1);
	mpz_set_ui(p_1, mpz_get_ui(p)-1);
	mpz_init(k);
	mpz_init(k_1);
	srand(time(NULL));
	mpz_set_ui(k, rand() % mpz_get_ui(p_1));
	
	// A zieht eine Zufallszahl k mit k < p-1 und ggT(k, p-1) = 1
	while(mpz_get_ui(gcd) != 1) {
		mpz_set_ui(gcd, 0);
		mpz_set_ui(k, rand() % mpz_get_ui(p_1));
		Get_GCD(gcd, k, p_1);
	}
	if (debug)
		printf("Found a k=%d\n", mpz_get_ui(k));

	//mpz_set_ui(k, 213); // Für Beispiel: 13, 213, 137

	// und berechnet r := w^k mod p
	mpz_powm(r, w, k, p);
	if (debug)
		printf("r = w^k mod p : r = %d ^ %d mod %d.\n", mpz_get_ui(w), mpz_get_ui(k), mpz_get_ui(p));

	// invert k mod (p-1) => k_1
	mpz_invert(k_1, k, p_1);
	if (debug)
		printf("k * k^(-1) = 1 mod (p-1) : %d * %d = 1 mod %d.\n", mpz_get_ui(k), mpz_get_ui(k_1), mpz_get_ui(p_1));

	// und s := (m - r*x_A) * k^(-1) mod (p-1)
	mpz_t tmp;
	mpz_init(tmp);
	mpz_mul(tmp, r, x);
	mpz_sub(s, mdc, tmp);
	mpz_mul(s, s, k_1);
	mpz_mod(s, s, p_1);

	if (debug)
		printf("s = (m - r*sk) * k^(-1) mod (p-1) : r = (%d - %d*%d) * %d mod (%d).\n", mpz_get_ui(mdc), mpz_get_ui(r), mpz_get_ui(x), mpz_get_ui(k_1), mpz_get_ui(p_1));

	if (debug)
		printf("r=%d, s=%d.\n", mpz_get_ui(r), mpz_get_ui(s));
}

int main2(int argc, char **argv)
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
	OurName = MakeNetName(NULL); /* gibt in Wirklichkeit Unix-Gruppenname zurück! */
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

int main(int argc, char **argv) 
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

	return 0;
}
