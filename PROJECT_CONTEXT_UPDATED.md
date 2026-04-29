# PROJECT CONTEXT UPDATED — WiFi Log Analyzer / UniFi SIEM Pipeline

## Stato attuale della pipeline
Pipeline consolidata su 4 layer: parser, canonicalizer, detection/enrichment, incident/analyst reporting. I layer core (parser/canonicalizer/detection) sono considerati stabili e non vanno toccati senza evidenza forte.

Metriche operative correnti (baseline condivisa):
- raw events: 15985
- parsed events: 15985
- canonical events: 2190
- unknown events: 0
- enriched events: 2190
- incident candidates: 1167
- final incidents: 6
- analyst_priority_distribution: P1=2, P2=2, P3=2

## Layer stabili (guardrail)
- Parser layer stabile: nessuna modifica richiesta su parsing/regex.
- Canonicalization layer stabile: nessuna modifica su mapping/typed canonical events.
- Detection/enrichment layer stabile: nessuna modifica su detection logic o enriched dataset completo.
- `enriched_canonical_events.json` deve restare completo (no filtering/no data loss).

## Incident builder aggiornato
È stato introdotto un doppio score per migliorare la prioritizzazione SOC senza alterare:
- `severity_score` originale
- `analyst_priority` originale

Distinzione tecnica:
- `operational_impact_score`: score normalizzato/capped (cap 120), leggibile per dashboard/bucket.
- `operational_impact_rank_score`: score di ordinamento reale (non capped a 120), usato solo per ranking operativo.

### Operational impact model (conservativo)
Formula leggibile e commentata nel codice:
- base: `severity_score`
- peso priorità analyst (P1>P2>P3)
- peso volume (`canonical_event_count`, con cap)
- peso durata incidente (`duration_seconds`, con cap)
- peso ampiezza impatto (numero `source_ips`, `radios`, `ap_macs`)
- peso tag critici:
  - `high_event_volume`
  - `repeated_disconnect`
  - `poor_rssi`
  - `wifi_security`
  - `incident_candidate`
- cap massimo: 120

Formula `operational_impact_rank_score` (deterministica e spiegabile):
- base: `severity_score`
- peso analyst priority: `P1=+50`, `P2=+25`, `P3=+10`, `noise=0`
- peso volume: `min(canonical_event_count / 10, 100)`
- peso durata: `min(duration_seconds / 60, 20)`
- peso ampiezza:
  - `source_ips_count * 5`
  - `radios_count * 5`
  - `ap_macs_count * 3`
- peso tag critici:
  - `high_event_volume=+15`
  - `repeated_disconnect=+15`
  - `poor_rssi=+10`
  - `wifi_security=+10`
  - `incident_candidate=+10`

Uso del rank score:
- ordinamento `top_true_incidents`
- ordinamento `top_problematic_clients`
- ordinamento `true_incidents_to_review` in `analyst_summary.json`
- ordinamento `what_to_investigate_first`

Tie-break operativo adottato:
1. `operational_impact_rank_score` DESC
2. `operational_impact_score` DESC
3. `severity_score` DESC
4. `canonical_event_count` DESC
5. `first_seen` ASC

## Analyst summary / Incident summary
I report analyst/SIEM restano viste operative, non trasformazioni distruttive dei dati.

### `analyst_summary.json`
- Incidenti reali ordinati per `operational_impact_rank_score` (con tie-break espliciti).
- Ogni true incident include `operational_impact_score` e `operational_impact_rank_score`.
- Sezione nuova: `what_to_investigate_first` con:
  - client prioritario
  - motivazione
  - AP/source_ip/radio coinvolti
  - evidenze principali
  - controlli operativi consigliati

### `incident_summary.json`
- `top_true_incidents` ordinati per `operational_impact_rank_score`.
- `top_problematic_clients` ordinati per impatto operativo reale.
- Campi aggiunti:
  - `total_suppressed_or_low_priority_events`
  - `noise_or_suppressed_breakdown`
  - `summary_note` (esplicita no data loss e natura analyst/SIEM view)
  - `operational_impact_rank_score` nei blocchi top incident/client

## Strategia suppression
La suppression è ammessa solo nel layer incident/reporting:
- `suppressed_single_event_count`
- `low_priority_patterns`
- noise UniFi (`noise_unifi_events`)

Nessun evento canonical/enriched viene eliminato dai dataset sorgente.

## Evidenze operative principali
I due client P1 principali da mantenere in focus operativo:
- `c4:82:e1:71:52:e0`
- `c4:82:e1:81:04:f9`

## Distinzione concettuale da preservare
- Enriched events completi: base dati forense/SIEM.
- Incidenti analyst/SIEM: vista operativa filtrata/prioritizzata.
- Noise/suppressed/low priority: classificazione di reporting, non perdita informativa.

## Cosa NON toccare senza motivo
- Parser e regex parsing
- Canonicalizer e tipi canonici
- Detection layer
- `enriched_canonical_events.json`
- Conteggi core (raw/parsed/canonical/enriched/unknown)

## File coinvolti in questa modifica
- `detection/incident_builder.py` (nuovo rank score, ordinamenti, campi output, ranking_factors)
- `PROJECT_CONTEXT_UPDATED.md` (documentazione tecnica aggiornata)

Core non toccato:
- parser invariato
- canonicalizer invariato
- detection/enrichment invariati
- nessun filtro/rimozione su `enriched_canonical_events.json`

## Prossimo step consigliato
Preparare export OpenSearch/SIEM (NDJSON) con schema campi stabile:
- mantenere `incident_summary.json` e `analyst_summary.json` come viste operative
- definire schema export per:
  - canonical enriched events
  - incidents
  - incident summary / analyst summary
- preservare separazione tra completezza dati e prioritizzazione analyst.
