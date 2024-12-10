#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct pkt_info {
    __u32 countPacchetti;       // Contatore totale dei pacchetti
    __u32 counterSec;           // Contatore dei pacchetti per l'ultimo secondo
    __u64 timevalAVG;           // Tempo medio per calcolare la media dei pacchetti al secondo
    __u64 last_time;            // Ultimo timestamp per il calcolo dell'IAT
    __u64 sum_iat;              // Somma degli intervalli di tempo per calcolare la media dell'IAT
};

// Definizione della mappa eBPF con chiave leggibile (IP in formato array di byte)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, unsigned char[4]);
    __type(value, struct pkt_info);
    __uint(max_entries, 1024);
} pkt_map SEC(".maps");

SEC("xdp")
int monitor_packets(struct xdp_md *ctx) {
    // Accesso ai dati del pacchetto
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Verifica se è un pacchetto IP
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Accesso all'intestazione IP
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    // Conversione dell'IP sorgente in un array di byte leggibile
    unsigned char ip_src[4];
    ip_src[0] = iph->saddr & 0xFF;
    ip_src[1] = (iph->saddr >> 8) & 0xFF;
    ip_src[2] = (iph->saddr >> 16) & 0xFF;
    ip_src[3] = (iph->saddr >> 24) & 0xFF;

    __u64 now = bpf_ktime_get_ns();

    // Cerca l'IP nella mappa
    struct pkt_info *info = bpf_map_lookup_elem(&pkt_map, &ip_src);
    struct pkt_info new_entry = {};

    if (info) {
        // Incrementa il contatore totale dei pacchetti
        info->countPacchetti++;
        info->counterSec++;

        // Calcola e aggiorna il timevalIAT
        if (info->last_time != 0) {
            __u64 iat = now - info->last_time;
            info->sum_iat += iat;
        }
        info->last_time = now;

        // Controlla se è passato più di 1 secondo per aggiornare il timevalAVG
        if (now - info->timevalAVG >= 1000000000ULL) { // 1 secondo in nanosecondi
            info->timevalAVG = now;

            // Resetta il contatore per il prossimo secondo
            info->counterSec = 1;
        }
    } else {
        // Inizializza un nuovo record se non esiste
        new_entry.countPacchetti = 1;
        new_entry.counterSec = 1;
        new_entry.timevalAVG = now;
        new_entry.last_time = now;
        new_entry.sum_iat = 0;
        bpf_map_update_elem(&pkt_map, &ip_src, &new_entry, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
