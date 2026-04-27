# PROJECT CONTEXT

## Obiettivo di questo giro
Ridurre in modo conservativo gli eventi `unknown`, classificando solo pattern sicuri e ricorrenti, senza toccare la logica di canonizzazione/deduplica.

## Baseline (prima)
Metriche di riferimento fornite:
- raw events: 15985
- parsed events: 15985
- canonical events: 2518
- unknown events exported: 276
- canonical unknown sequences: 219
- wifi security sequences: 12
- known event types inside unknown sequences: 0

## Modifiche introdotte (minime e sicure)
Sono state aggiunte classificazioni solo per famiglie chiaramente identificabili:

1. **Lifecycle syslog/logread**
   - `syslogd_lifecycle` (categoria: `system_logging`)
   - `logread_lifecycle` (categoria: `system_logging`)
   - Attivate solo quando il `process_name` è rispettivamente `syslogd` o `logread` e il testo contiene verbi di lifecycle inequivocabili (start/restart/exiting/listening/stop).

2. **DHCP assignment esplicito**
   - `dhcp_ip_assignment` (categoria: `network_dhcp`)
   - Trigger solo su pattern ACK chiari (`DHCPACK(...)`, `sending ACK to ...`).
   - Se presente un MAC nel messaggio, viene valorizzato in `client_mac`/`mac`.

3. **Link state esplicito**
   - `network_link_up` (categoria: `network_link`)
   - `network_link_down` (categoria: `network_link`)
   - Trigger solo su pattern testuali espliciti di link up/down.

## Verifiche eseguite
- Test unitari parser/classificazione aggiornati con nuovi casi per:
  - syslogd/logread lifecycle
  - DHCP ACK con MAC
  - link up/down
- Nessuna modifica a deduplica/canonizzazione.
- Nessuna rimozione di campi evento.
- `raw_line` e `raw_message` invariati.

## Metriche dopo (stato locale)
Nel container corrente non è disponibile il dataset `data/raw/syslog`, quindi non è stato possibile calcolare localmente le metriche complete prima/dopo con `main.py`.

Comando tentato:
- `PYTHONPATH=. python main.py` -> fallisce per `FileNotFoundError: data/raw/syslog`

## Pattern lasciati unknown (intenzionalmente)
Qualsiasi pattern ambiguo/non inequivocabile resta `unknown` / `system_event` per evitare falsi positivi.
