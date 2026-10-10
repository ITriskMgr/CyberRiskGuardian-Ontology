# Making https://w3id.org/crgo/ resolve

The ontology's identifiers (`https://w3id.org/crgo/...`) are w3id.org permanent identifiers. They resolve once two things are in place. Neither can be done from the build session: both need the repository owner.

## 1. Publish the documentation site (GitHub Pages)

In GitHub, open **ITriskMgr/cyberriskguardian-ontology → Settings → Pages**, choose **Deploy from a branch**, branch **main**, folder **/docs**, and save. After a minute the site is at https://itriskmgr.github.io/cyberriskguardian-ontology/.

## 2. Register the w3id.org redirect

1. Fork https://github.com/perma-id/w3id.org.
2. Copy the folder `w3id/crgo/` of this repository (it holds `.htaccess` and `README.md`) to the root of the fork, as `crgo/`.
3. Open a pull request titled "Add /crgo (CyberRiskGuardian Ontology)". The w3id maintainers usually merge within a few days.

## 3. Push the release tags

Version IRIs such as `https://w3id.org/crgo/0.4.0/crgo-core` resolve to the files at tag `v0.4.0`. The tags exist in the local build only; create them on GitHub (**Releases → Draft a new release**, tag `v0.1.0` … `v0.4.0` on the matching commits listed in `CHANGELOG.md`).

## Checking

After the merge: `curl -sIL -H "Accept: text/turtle" https://w3id.org/crgo/crgo-core` should end at the Turtle file, and opening `https://w3id.org/crgo/CRGO_0000002` in a browser should land on "information asset" in the documentation.
