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
		if (debug)
			gmp_printf("i=%d, factor=%Zd, tmp=%Zd\n", i, factorlist[i], tmp);
	}
	mpz_add_ui(tmp, tmp, 1);
	if (mpz_cmp(tmp, p)) {
		printf ("FATAL: Faktoren stammen nicht von p-1!\n");
		exit (1);
	}
	mpz_clear(tmp);
}

/*
	Compare function for qsort BSGSElements
*/
int comparator(const void* a, const void* b) {
	mpz_t g, h;
	mpz_init_set(g, ((const BSGSElement*)a)->w_i);
	mpz_init_set(h, ((const BSGSElement*)b)->w_i);
	if (debug)
		gmp_printf("a=%Zd, b=%Zd.\n", a, b);
	return mpz_cmp(g, h);
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
	mpz_t q_i, inv_w_q, tmp;
	mpz_init(q_i);
	mpz_sqrt(q_i, p_i);
	mpz_add_ui(q_i, q_i, 1);  // lets go on number safer.
	if (debug)
		gmp_printf("%Zd Elemente.\n", q_i);

	// this will be out list (w^i, i) for the baby steps
	BSGSElement* list;
	list = malloc(mpz_get_ui(q_i) * sizeof(BSGSElement));
	mpz_init_set_ui(list[0].w_i, 1);
	list[0].index = 0;
	if (debug)
		gmp_printf("%d. Adding %Zd.\n", 0, list[0].w_i);

	int i;
	for (i = 1; i < mpz_get_ui(q_i); i++) {
		list[i].index = i;
		mpz_init(list[i].w_i);
		mpz_mul(list[i].w_i, list[i-1].w_i, w_i); //gmp_printf("%Zd * %Zd = %Zd.\n%Zd mod %Zd", list[i].w_i, w_i, list[i+1].w_i, list[i+1].w_i, p);
		mpz_mod(list[i].w_i, list[i].w_i, p); //gmp_printf(" = %Zd.\n", list[i+1].w_i);
		if (debug)
			gmp_printf("%d. Adding %Zd.\n", i, list[i].w_i);
	}
	if (debug) {
		for (int i = 0; i < mpz_get_ui(q_i); i++) {
			gmp_printf("%d. %Zd\n", list[i].index, list[i].w_i);
		}
	}
	qsort((void*)list, mpz_get_ui(q_i), sizeof(list[0]), comparator);	// sort list for values, not indices
	if (debug) {
		for (int i = 0; i < mpz_get_ui(q_i); i++) {
			gmp_printf("%d. %Zd\n", list[i].index, list[i].w_i);
		}
	}
	mpz_init_set(inv_w_q, w_i);
	mpz_powm(inv_w_q, inv_w_q, q_i, p);	// compute (w_i ^ q_i mod p)^(-1)
	if (debug)
		gmp_printf("Inverse of %Zd is ", inv_w_q);
	mpz_invert(inv_w_q, inv_w_q, p);
	if (debug)
		gmp_printf("%Zd.\n", inv_w_q);

	mpz_init_set(tmp, a_i);
	BSGSElement* bsgs_tmp = malloc(sizeof(BSGSElement));
	mpz_init(bsgs_tmp->w_i);


	BSGSElement* j;
	for (i = 0; i < mpz_get_ui(q_i); i++) {
		// search for tmp in our list
		mpz_set(bsgs_tmp->w_i, tmp);
		if (debug)
			gmp_printf("%d. Searching for: %Zd.\n", i, tmp);
		j = (BSGSElement*) bsearch(bsgs_tmp, list, mpz_get_ui(q_i), sizeof(BSGSElement), comparator);
		if (j != NULL) {
			if (debug)
				gmp_printf("Found a y_i and a z_i which satisfies x_i [=] y_i + q_i * z_i : %d + %d * %Zd = ", j->index, i, q_i);
			mpz_mul_ui(q_i, q_i, i);
			mpz_add_ui(q_i, q_i, j->index);
			mpz_set(x_i, q_i);
			if (debug)
				gmp_printf("%Zd.\n", x_i);
			break;
		}
		// not found. update tmp
		mpz_mul(tmp, tmp, inv_w_q);
		mpz_mod(tmp, tmp, p);
	}
	mpz_clears(q_i, inv_w_q, tmp, NULL);
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
	int i;
	mpz_t p_1, tmp, a_i, w_i, p_i, inv;
	mpz_t* x_is = malloc(nfactors * sizeof(mpz_t));
	mpz_t* crt_x_is = malloc(nfactors * sizeof(mpz_t));
	mpz_init(p_1);
	mpz_init(a_i);
	mpz_init(w_i);
	mpz_init(p_i);
	mpz_init(inv);
	mpz_init_set_ui(tmp, 0);
	mpz_sub_ui(p_1, p, 1);

	for (i = 0; i < nfactors; i++) {
		mpz_set(p_i, factorlist[i]);
		mpz_div(tmp, p_1, p_i);      // tmp = p-1 / p_i
		mpz_powm(w_i, w, tmp, p);	 // w_i = w ^ (p-1 / p_i) mod p
		mpz_mul(tmp, tmp, tmp);      // tmp = (p-1 / p_i)²
		mpz_powm(a_i, y, tmp, p);	 // a_i = a ^ (p-1 / p_i)² mod p
		if (debug)
			gmp_printf("%d. BSGS for a_i=%Zd, w_i=%Zd, p_i=%Zd.\n With p=%Zd\n", i, a_i, w_i, p_i, p);
		mpz_init(x_is[i]);
		babyStepGiantStep(x_is[i], a_i, w_i, p_i);
	}
	if (debug) {
		for (i = 0; i < nfactors; i++) {
			gmp_printf("prime[%d] = %Zd. x[%d] = %Zd.\n", i, factorlist[i], i, x_is[i]);
		}
	}
	// now we got our crt-values, time to do some math
	for (i = 0; i < nfactors; i++) {
		mpz_init(crt_x_is[i]);
		mpz_div(tmp, p_1, factorlist[i]);						// compute tmp = (p-1) / p_i
		mpz_invert(tmp, tmp, factorlist[i]);					// tmp^(-1)
		mpz_mul(crt_x_is[i], x_is[i], tmp);						// x_i * tmp^(-1)
		mpz_mod(crt_x_is[i], crt_x_is[i], factorlist[i]);		// x_i * tmp^(-1) mod p_i
		if (debug)
			gmp_printf("%d. x = %Zd mod %Zd.\n", i, crt_x_is[i], factorlist[i]);
	}
	mpz_t x_p, x_q, p_inv, z, p_q;
	mpz_init(x_p); mpz_init(x_q); mpz_init(p_inv); mpz_init(z); mpz_init(p_q);
	
	mpz_mod(z, x_is[0], factorlist[0]);
	mpz_set(p_q, factorlist[0]);

	mpz_t p, prod, sum;
	mpz_init(p); mpz_init_set_ui(prod, 1); mpz_init_set_ui(sum, 0);

	for (i = 0; i < nfactors; i++)
		mpz_mul(prod, prod, factorlist[i]);

	for (i = 0; i < nfactors; i++) {
		mpz_div(p, prod, factorlist[i]);
		mpz_invert(p_inv, p, factorlist[i]);
		mpz_mul(tmp, p_inv, p);
		mpz_mul(tmp, crt_x_is[i], tmp);
		mpz_add(sum, sum, tmp);
	}
	mpz_mod(tmp, sum, prod);
	mpz_set(x, tmp);
	if (debug)
		gmp_printf("sum=%Zd, prod=%Zd, x=%Zd.\n", sum, prod, tmp);
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

	mpz_init_set_ui(gcd, 0);
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
	mpz_t x, Daemon_y, Daemon_x, mdc, sign_s, sign_r, fake_x;
	char *OurName = "manton";
	char* fake_report[10];

	mpz_init(x);
	mpz_init(Daemon_y);
	mpz_init(Daemon_x);
	mpz_init(mdc);
	mpz_init(sign_s);
	mpz_init(sign_r);
	mpz_init(p);
	mpz_init(w);
	mpz_init(fake_x);

	/**************  Laden der öffentlichen und privaten Daten  ***************/
	if (!Get_Private_Key(NULL, p, w, x) || !Get_Public_Key(DAEMON_NAME, Daemon_y)) exit(0);


	/********************  Verbindung zum Dämon aufbauen  *********************/
	//OurName = "manton";// MakeNetName(NULL); /* gibt in Wirklichkeit Unix-Gruppenname zurück! */
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
	
	dlogP(fake_x, Daemon_y);

	if (mpz_cmp(x, fake_x)) {
		printf("Right fake key.\n");
	} else {
		printf("Wrong fake key.\n");
	}

	if (!(con=ConnectTo(OurName,DAEMON_NAME))) {
		fprintf(stderr,"Kann keine Verbindung zum Daemon aufbauen: %s\n",NET_ErrorText());
		exit(20);
	}

	/***********  Message vom Typ ReportRequest initialisieren  ***************/
	msg.typ  = VerifyRequest;                       /* Typ setzten */
	msg.body.VerifyRequest.NumLines = 3;    /* Gruppennamen eintragen */
	strcpy(msg.body.VerifyRequest.Report[0],("Der Teilnehmer %s hat in den Versuchen", OurName));    /* Nachricht eintragen */
	strcpy(msg.body.VerifyRequest.Report[1],"1 bis 7 bereits die erforderliche Punkte-");    /* Nachricht eintragen */
	strcpy(msg.body.VerifyRequest.Report[2],"zahl erreicht. Ein Schein wird daher gewährt."); /* Nachricht eintragen */
	Generate_MDC(&msg, p, mdc);                     /* MDC generieren ... */
	Generate_Sign(mdc, sign_r, sign_s, fake_x);          /* ... und Nachricht unterschreiben */
	strcpy(msg.sign_r, mpz_get_str(NULL, 16, sign_r));
	strcpy(msg.sign_s, mpz_get_str(NULL, 16, sign_s));

	/*************  Machricht abschicken, Antwort einlesen  *******************/
	if (Transmit(con,&msg,sizeof(msg))!=sizeof(msg)) {
		fprintf(stderr,"Fehler beim Senden des 'VerifyRequest': %s\n",NET_ErrorText());
		exit(20);
	}

	if (Receive(con,&msg,sizeof(msg))!=sizeof(msg)) {
		fprintf(stderr,"Fehler beim Empfang des 'VerifyResponse': %s\n",NET_ErrorText());
		exit(20);
	}


	/******************  Überprüfen der Dämon-Signatur  ***********************/
	printf("Nachricht vom Dämon:\n");
	printf("\t%s\n",msg.body.VerifyResponse.Res);
	

	mpz_clears(x, Daemon_y, Daemon_x, mdc, sign_s, sign_r, p, w, NULL);

	return 0;
}


/*
	Testings for the algorithms.
*/
int main2(int argc, char **argv) 
{
	mpz_t mdc, r, s, sk, pk, x, a, t, u, v;

	mpz_init_set_ui(mdc, 168); // 10, 100, 168
	mpz_init_set_ui(r, 975);
	mpz_init_set_ui(s, 4);
	mpz_init_set_ui(sk, 127); // 11, 127, 66
	mpz_init_set_ui(pk, 132); // 7, 132, 1452
	
	mpz_init_set_ui(p, 673); // 17, 467, 4679
	mpz_init_set_ui(w, 2); // 3, 2, 807

	mpz_init_set_ui(t, 350);
	mpz_init_set_ui(u, 100);
	mpz_init_set_ui(v, 350);
	mpz_init_set_ui(a, 1020);
	mpz_init_set_ui(x, 999);

	BSGSElement* t_b = malloc(9 * (sizeof(BSGSElement)));
	BSGSElement* hu1 = malloc(sizeof(BSGSElement));
	BSGSElement* hu2 = malloc(sizeof(BSGSElement));
	mpz_init_set(hu1->w_i, x); hu1->index = 1;
	mpz_init_set(hu2->w_i, a); hu2->index = 2;
	mpz_init_set(t_b[0].w_i, mdc);   t_b[0].index = 0;
	mpz_init_set(t_b[1].w_i, r);    t_b[1].index = 1;
	mpz_init_set(t_b[2].w_i, s);    t_b[2].index = 2;
	mpz_init_set(t_b[3].w_i, sk);   t_b[3].index = 3;
	mpz_init_set(t_b[4].w_i, pk);   t_b[4].index = 4;
	mpz_init_set(t_b[5].w_i, a);    t_b[5].index = 5;
	mpz_init_set(t_b[6].w_i, t);   t_b[6].index = 6;
	mpz_init_set(t_b[7].w_i, u);   t_b[7].index = 7;
	mpz_init_set(t_b[8].w_i, v);   t_b[8].index = 8;
/*
	int size = 9;

	for (int i = 0; i < size; i++) {
		gmp_printf("%d. %d\n", t_b[i].index, mpz_get_ui(t_b[i].w_i));
	}
	printf("\n");
	qsort((void*)t_b, size, sizeof(t_b[0]), comparator);

	for (int i = 0; i < size; i++) {
		gmp_printf("%d. %d\n", t_b[i].index, mpz_get_ui(t_b[i].w_i));
	}

	BSGSElement* hugo;
	hugo = (BSGSElement*)bsearch(hu2, t_b, size, sizeof(t_b[0]), comparator);
	if (hugo != NULL) {printf("First found. hugo = %d.\n", hugo->index);} else {printf("First not found. hugo = %d.\n", 3);}
	hugo = (int*)bsearch(hu1, t_b, size, sizeof(t_b[0]), comparator);
	if (hugo != NULL) {printf("Second found. hugo = %d.\n", hugo->index);} else {printf("Second not found hugo = %d.\n", 33);}
*/
	mpz_init(x);
	mpz_init(a);
	mpz_powm(a, w, sk, p);

	Generate_Sign(mdc, r, s, sk); // (12, 14), (29, 51)
	Verify_Sign(mdc, r, s, pk);


	mpz_t b_x, b_a, b_w, b_p;
	mpz_init_set_ui(b_x, 0);
	mpz_init_set_ui(b_a, 3);
	mpz_init_set_ui(b_w, 11);
	mpz_init_set_ui(b_p, 29);
	//babyStepGiantStep(b_x, b_a, b_w, b_p);

	nfactors = 5;
	mpz_set_ui(p, 98533);
	mpz_set_ui(sk, 199);
	mpz_powm(b_w, w, sk, p);
	dlogP(b_x, b_w);

	mpz_clears(mdc, r, s, sk, pk, NULL);

	return 0;
}
