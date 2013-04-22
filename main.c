#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "callback.h"



void print_usage(void);



void print_usage()
{
    printf("Usage: sniffer [Options]\n"
           "Options:\n"
           "  -h                Affiche cette information seulement\n"
           "  -l                Effectue une analyse en mode non promiscuous\n"
           "                    (observation des paquets limitee a la machine locale)\n"
           "  -n <nombre>       Limite le nombre de paquets a analyser\n"
           "  -i <interface>    Effectue une analyse live sur cette interface reseau\n"
           "                    (si non specifie, utilise l'interface par defaut)\n"
           "  -o <fichier>      Effectue une analyse offline avec ce fichier d'entree\n"
           "  -f <filtre>       Specifie un filtre BPF a utiliser pour l'analyse live\n"
           "  -v <1..3>         Specifie le niveau de verbosité pour l'affichage en console\n"
           "                    (1=très concis ; 2=synthétique ; 3=complet)\n");
}



int main(int argc, char ** argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    pcap_t * handle = NULL;
    bpf_u_int32 net;                // adresse du reseau
    bpf_u_int32 mask;               // masque du reseau
    char * interface = NULL;        // interface reseau a sniffer
    char * file = NULL;             // fichier d'entree pour l'analyse
    char * filtre = NULL;           // filtre a appliquer a la capture live
    int verbose = 1;                // niveau de verbosite
    char args[2] = {'1', 0};        // argument du callback (verbosite)
    struct bpf_program cfilter;     // filtre BPF
    int count = -1;                 // nombre de paquets a analyser
    int promiscuous = 1;            // analyse en promiscuous ou non
    char c = 10;
    
    while ((c = getopt(argc, argv, "hln:i:o:f:v:")) != -1)
    {
        switch (c)
        {
            case 'h':
                print_usage();
                return EXIT_SUCCESS;
                break;
            case 'l':
                promiscuous = 0;
                break;
            case 'n':
                count = atoi(optarg);
                break;
            case 'i':
                interface = optarg;
                break;
            case 'o':
                file = optarg;
                break;
            case 'f':
                filtre = optarg;
                break;
            case 'v':
                verbose = atoi(optarg);
                break;
            default:
                print_usage();
                return EXIT_FAILURE;
        }
    }
    
    if (interface != NULL && file != NULL)
    {
        printf("Impossible d'effectuer une analyse a la fois en ligne et sur un fichier\n");
        return EXIT_FAILURE;
    }
    
    if (file != NULL && filtre != NULL)
        printf("Filtre inapplicable pour l'analyse a partir d'un fichier\n");
    
    if (file != NULL && filtre != NULL)
        printf("Limitation du mode d'analyse inapplicable pour l'analyse a partir d'un fichier\n");
    
    if (file != NULL)   /***** initialisation pour l'analyse sur fichier ******/
    {
        if ((handle = pcap_open_offline(file, errbuf)) == NULL)
        {
            printf("Impossible d'ouvrir l'interface: %s\n", errbuf);
            return EXIT_FAILURE;
        }
    }
    else                /********* initialisation pour l'analyse live *********/
    {
        if (interface == NULL)
        {
            printf("Interface reseau non specifiee: utilisation de l'interface par defaut\n");
            
            if ((interface = pcap_lookupdev(errbuf)) == NULL)
            {
                printf("Impossible de trouver l'interface par défaut: %s\n", errbuf);
                return EXIT_FAILURE;
            }
        }
        
        if (pcap_lookupnet(interface, &net, &mask, errbuf) != 0)
        {
            printf("Impossible de recuperer les informations de l'interface: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        
        if ((handle = pcap_open_live(interface, BUFSIZ, promiscuous, 1000, errbuf)) == NULL)
        {
            printf("Impossible d'ouvrir l'interface: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        
        if (interface != NULL && filtre != NULL)
        {
            if (pcap_compile(handle, &cfilter, filtre, 0, mask) != 0)
            {
                printf("Impossible de compiler l'expression de filtrage: %s\n", errbuf);
                return EXIT_FAILURE;
            }
            
            if (pcap_setfilter(handle, &cfilter) != 0)
            {
                printf("Impossible d'appliquer l'expression filtrante: %s\n", errbuf);
                return EXIT_FAILURE;
            }
        }
    }
    
    snprintf(args, 2, "%d", verbose);
    
    printf("================================================================================\n");
    
    if (pcap_loop(handle, count, my_callback, (u_char *)args) != 0)
    {
        printf("Erreur pendant l'analyse de trames\n");
        return EXIT_FAILURE;
    }
    
    pcap_close(handle);
    
    return EXIT_SUCCESS;
}

