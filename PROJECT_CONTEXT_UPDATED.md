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
È stato introdotto un ranking separato chiamato `operational_impact_score` per migliorare la prioritizzazione SOC senza alterare:
- `severity_score` originale
- `analyst_priority` originale

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

Uso del nuovo score:
- ordinamento `top_true_incidents`
- ordinamento `top_problematic_clients`
- ordinamento `true_incidents_to_review` in `analyst_summary.json`

## Analyst summary / Incident summary
I report analyst/SIEM restano viste operative, non trasformazioni distruttive dei dati.

### `analyst_summary.json`
- Incidenti reali ordinati per `operational_impact_score` decrescente.
- Ogni true incident include `operational_impact_score`.
- Sezione nuova: `what_to_investigate_first` con:
  - client prioritario
  - motivazione
  - AP/source_ip/radio coinvolti
  - evidenze principali
  - controlli operativi consigliati

### `incident_summary.json`
- `top_true_incidents` ordinati per `operational_impact_score`.
- `top_problematic_clients` ordinati per impatto operativo reale.
- Campi aggiunti:
  - `total_suppressed_or_low_priority_events`
  - `noise_or_suppressed_breakdown`
  - `summary_note` (esplicita no data loss e natura analyst/SIEM view)

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

## Prossimo step consigliato
Preparare export OpenSearch/SIEM (NDJSON) con schema campi stabile:
- mantenere `incident_summary.json` e `analyst_summary.json` come viste operative
- definire schema export per:
  - canonical enriched events
  - incidents
  - incident summary / analyst summary
- preservare separazione tra completezza dati e prioritizzazione analyst.
