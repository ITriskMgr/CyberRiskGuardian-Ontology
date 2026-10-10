# Making https://w3id.org/crgo/ resolve

The ontology's identifiers (`https://w3id.org/crgo/...`) are w3id.org permanent identifiers. They resolve once two things are in place. Neither can be done from the build session: both need the repository owner.

## 1. Publish the documentation site (GitHub Pages)

In GitHub, open **ITriskMgr/cyberriskguardian-ontology → Settings → Pages**, choose **Deploy from a branch**, branch **main**, folder **/docs**, and save. After a minute the site is at https://itriskmgr.github.io/CyberRiskGuardian-Ontology/.

## 2. Register the w3id.org redirect

1. Fork https://github.com/perma-id/w3id.org.
2. Copy the folder `w3id/crgo/` of this repository (it holds `.htaccess` and `README.md`) into the fork as `ids/crgo/` (w3id.org serves only `ids/`).
3. Commit both files in one commit with a descriptive message (for example "Add redirect for crgo (CyberRiskGuardian Ontology)"); w3id.org's checks reject GitHub's default messages. Their checker can be run locally: `node tools/check/bin/w3id-check.js ids/crgo`.
4. Open a pull request titled "Add /crgo (CyberRiskGuardian Ontology)". Submitted 2026-10-10 as perma-id/w3id.org#6858.

## 3. Release tags

Version IRIs such as `https://w3id.org/crgo/0.4.0/crgo-core` resolve to the files at tag `v0.4.0`. Tags v0.1.0 to v0.5.0 exist on GitHub (created 2026-10-10); for later releases, create them on GitHub (**Releases → Draft a new release**, tag `v0.1.0` … `v0.4.0` on the matching commits listed in `CHANGELOG.md`).

## Checking

After the merge: `curl -sIL -H "Accept: text/turtle" https://w3id.org/crgo/crgo-core` should end at the Turtle file, and opening `https://w3id.org/crgo/CRGO_0000002` in a browser should land on "information asset" in the documentation.
