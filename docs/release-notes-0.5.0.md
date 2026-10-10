# CRGO 0.5.0 — release notes (draft)

**Status:** draft for the project owner's review. Version 0.5.0 adds no classes, properties or axioms to 0.4.0; it prepares the ontology for publication.

## What is new

- **Documentation site.** A bilingual (English and French) WIDOCO site describing every class, property and individual of the four modules, with a WebVOWL diagram and downloads in Turtle, RDF/XML, N-Triples and JSON-LD. Landing page `docs/index.html`; documentation `docs/doc/index-en.html` and `index-fr.html`.
- **Permanent identifiers.** Rules for `https://w3id.org/crgo/`: browsers get the documentation (each term opens at its own entry), RDF clients get the Turtle files, version IRIs point to the files at the matching release tag. Tested against all 31,386 CRGO IRIs in the published files.
- **Metadata.** Each module now states its abstract and description in both languages, publisher, contributors (including the AI drafting assistant), dates, prior version, status and how to cite it.
- **Release files.** `CHANGELOG.md`, `CITATION.cff` and the extension plan `docs/roadmap.md`.

## What stays proposed

Unchanged from 0.4.0: the 1,742 low-confidence links, the R-22.1 rule links, the links of scenarios F1812–F1814, second themes and case-scenario matches. They carry status *proposed* on their annotations and are listed in `docs/roadmap.md` §1.

## To publish (needs the repository owner)

1. Enable GitHub Pages (Settings → Pages → main, `/docs`).
2. Push the tags `v0.1.0` … `v0.4.0` (and `v0.5.0` when approved).
3. Submit `w3id/crgo/` to perma-id/w3id.org (`w3id/HOWTO.md`).

## Checks

HermiT and ELK consistent; OWL 2 DL profile; fixtures and negative fixtures; metadata (all terms approved); vocabularies; MediBec round trip; crgo-full consistent; SHACL conforms; no critical pitfall; 20 of 20 competency questions; identification tests; w3id rules.
