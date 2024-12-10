# Tracciamento di Flussi Malevoli in Kathara tramite eBPF

**Autori:**  
- Leonardo Crozzoli (matr. 576633)  
- Lorenzo Benzi (matr. 578295)  
**Relatore:** Tommaso Caiazzi (Kathara Team)

## Introduzione

In questa repository troverete la raccolta delle directory e dei file legati al nostro studio per la tesi, il cui obiettivo principale è sperimentare, all’interno dell’ambiente di emulazione di rete [Kathara](https://github.com/KatharaFramework/Kathara) tecniche avanzate per il tracciamento di flussi malevoli attraverso l’impiego di programmi **eBPF**.

Nel mondo della sicurezza informatica monitoriamo i flussi di traffico della rete per individuare attività anomale e potenzialmente dannose.  
Intercettare precocemente un attacco informatico può ridurre enormemente l’impatto sui sistemi e sull’infrastruttura di rete.

## Cos’è Kathara?

**Kathara** è un framework di emulazione di rete che consente di creare e sperimentare topologie complesse in modo rapido e flessibile. Basato su container Linux, Kathara rende possibile la configurazione di router, switch, host e servizi vari in maniera modulare. Grazie a questo ambiente, possiamo simulare scenari di rete realistici e valutare il comportamento di protocolli, soluzioni di sicurezza e sistemi di monitoraggio senza dover disporre di costose infrastrutture fisiche.

## Che cos’è un attacco DDoS?

Un attacco **DDoS (Distributed Denial of Service)** è una tipologia di aggressione informatica in cui molteplici fonti malevole inviano un volume enorme di richieste a un target specifico (un server, un servizio online, un sito web), con l’obiettivo di sovraccaricarlo e impedirne il normale funzionamento. Un DDoS ostacola l’accesso alle risorse della rete da parte degli utenti legittimi, generando danni economici e d’immagine.

## Cosa sono i programmi eBPF?

**eBPF (Extended Berkeley Packet Filter)** è una tecnologia integrata nel kernel Linux che permette di analizzare, filtrare e modificare il traffico di rete “al volo”. A differenza di sistemi tradizionali, eBPF consente di inserire piccoli programmi direttamente all’interno del kernel, senza necessità di ricompilarlo o di utilizzare moduli esterni. Questi si distinguono per:

- **Efficienza:** Operano vicino al core del sistema, riducendo latenze e overhead.  
- **Flessibilità:** Possono essere aggiornati a caldo, consentendo l’evoluzione dinamica delle logiche di filtraggio.  
- **Sicurezza:** Il modello di sicurezza di eBPF verifica i programmi prima dell’esecuzione, riducendo il rischio di causare instabilità al kernel.

In pratica, eBPF fornisce una visibilità granulare sui flussi di rete e sul comportamento delle applicazioni in tempo reale. Ciò permette di identificare tempestivamente attività sospette, intervenendo prima che compromettano la stabilità dell’intera infrastruttura.

## Obiettivi del Progetto

1. **Emulazione di scenari reali con Kathara:**  
   Riprodurre un ambiente di rete complesso che simuli situazioni realistiche, incluse topologie con molteplici sorgenti e destinazioni, protocolli eterogenei e percorsi dinamici.

2. **Tracciamento di flussi malevoli:**  
   Utilizzare programmi eBPF per analizzare il traffico di rete, individuando flussi anomali tipici di attacchi DDoS. L’obiettivo è riconoscere segnali precoci di sovraccarico, isolando le fonti malevole.

3. **Validazione e valutazione:**  
   Valutare l’efficacia delle soluzioni proposte in termini di precisione (capacità di individuare il traffico malevolo con pochi falsi positivi), prestazioni (latenza aggiuntiva e overhead) e robustezza (adattabilità a nuovi tipi di attacco).

## Struttura della Repo

La repository è organizzata come segue:

- **/config**: File di configurazione per Kathara, inclusi gli script per la creazione dell’ambiente emulato.  
- **/ebpf**: Codice sorgente dei programmi eBPF, inclusi esempi e script per il caricamento e la gestione.  
- **/tests**: Script e tool per simulare attacchi DDoS e testare la capacità del sistema di identificarli.  
- **/docs**: Documentazione di approfondimento sul progetto, note tecniche e risultati delle sperimentazioni.

## Conclusioni

Questo progetto mira a coniugare tecniche di emulazione di rete (Kathara) con l’analisi dinamica del traffico (eBPF) per individuare flussi malevoli tipici degli attacchi DDoS. Individuare tempestivamente le minacce permette di prevenirne la diffusione, garantendo sistemi più stabili, efficienti e sicuri.
