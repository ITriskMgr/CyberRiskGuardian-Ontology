const D=__DATA__;
const META=__META__;
const BASE="https://w3id.org/crgo/";
const FAMS={
 core:{en:"risk model",fr:"modèle de risque",mods:["gov","core","measure","crg"]},
 evid:{en:"evidence and context",fr:"preuves et contexte",mods:["evidence","org","vuln"]},
 grc:{en:"governance, policy and compliance",fr:"gouvernance, politiques et conformité",mods:["grc","mapping","governance","policy","compliance"]},
 assur:{en:"assurance and audit",fr:"assurance et audit",mods:["assurance","audit"]},
 ops:{en:"security operations",fr:"opérations de sécurité",mods:["incident","siem","soar"]}};
const MODS={gov:{en:"governance metadata",fr:"métadonnées de gouvernance"},core:{en:"core",fr:"noyau"},measure:{en:"measures",fr:"mesures"},crg:{en:"CRG method",fr:"méthode CRG"},
 evidence:{en:"sources and observations",fr:"sources et observations"},org:{en:"organisation profile",fr:"profil d'organisation"},vuln:{en:"vulnerability observations",fr:"observations de vulnérabilités"},
 grc:{en:"legal applicability",fr:"applicabilité juridique"},mapping:{en:"correspondences",fr:"correspondances"},governance:{en:"corporate governance",fr:"gouvernance d'entreprise"},
 policy:{en:"policy management",fr:"gestion des politiques"},compliance:{en:"compliance management",fr:"gestion de la conformité"},
 assurance:{en:"assurance",fr:"assurance"},audit:{en:"audit",fr:"audit"},incident:{en:"events and incidents",fr:"événements et incidents"},
 siem:{en:"monitoring and detection (SIEM)",fr:"surveillance et détection (SIEM)"},soar:{en:"response (SOAR)",fr:"réponse (SOAR)"}};
const famOf={};Object.entries(FAMS).forEach(([f,v])=>v.mods.forEach(m=>famOf[m]=f));
const T={
 en:{map:"map",lhub:"The arrows are the ontology's own relations. Click a box to see its definition and all of its relations in the panel below.",
  all:"All classes, by kind of thing",lall:"Each column is a BFO category; indentation shows subclasses and colour shows the module family. The number on a value list is how many values it holds.",
  voc:"Reference vocabularies",lvoc:"SKOS concept schemes held next to the OWL modules (number of concepts). Library scenarios, controls and obligations link to them; framework identifiers keep their owners' terms.",
  classes:"classes",rels:"relations",attrs:"attributes",scen:"library scenarios",links:"scenario–framework links",concepts:"vocabulary concepts",
  out:"Relations from this class",inn:"Relations pointing to this class",data:"Attributes",vals:"Values",parent:"Is a kind of",sub:"Subclasses",none:"None declared.",inh:"inherited from",
  pick:"Select a class",pickt:"Click a box in a diagram or a class in the columns to see its definition, its place in BFO and its relations.",find:"Find a class…",newin:"new in",
  req:"framework concepts",reqs:"SKOS · CSF · 800-53 · ISO",vocabnote:"Concepts of the framework vocabularies (SKOS), not OWL classes. Library scenarios link to them with “has relevant requirement”, each link carrying a confidence and a review status."},
 fr:{map:"carte",lhub:"Les flèches sont les relations de l’ontologie. Cliquez sur une boîte pour voir sa définition et toutes ses relations dans le panneau plus bas.",
  all:"Toutes les classes, par sorte d’entité",lall:"Chaque colonne est une catégorie de BFO; le retrait indique les sous-classes et la couleur la famille de modules. Le nombre sur une liste de valeurs indique combien de valeurs elle contient.",
  voc:"Vocabulaires de référence",lvoc:"Schémas de concepts SKOS tenus à côté des modules OWL (nombre de concepts). Les scénarios de la bibliothèque, les mesures et les obligations y sont liés; les identifiants des référentiels restent soumis aux conditions de leurs propriétaires.",
  classes:"classes",rels:"relations",attrs:"attributs",scen:"scénarios de bibliothèque",links:"liens scénario–référentiel",concepts:"concepts de vocabulaire",
  out:"Relations à partir de cette classe",inn:"Relations vers cette classe",data:"Attributs",vals:"Valeurs",parent:"Est une sorte de",sub:"Sous-classes",none:"Aucune déclarée.",inh:"héritée de",
  pick:"Choisir une classe",pickt:"Cliquez sur une boîte d’un diagramme ou une classe dans les colonnes pour voir sa définition, sa place dans BFO et ses relations.",find:"Chercher une classe…",newin:"nouveau en",
  req:"concepts de référentiels",reqs:"SKOS · CSF · 800-53 · ISO",vocabnote:"Concepts des vocabulaires de référentiels (SKOS), et non des classes OWL. Les scénarios de la bibliothèque y sont liés par « a une exigence pertinente », chaque lien portant une confiance et un statut de révision."}};
let L="en", sel=null, active=new Set(Object.keys(FAMS)), query="", hubKey="risk";
try{const s=JSON.parse(localStorage.getItem("crgo-map")||"{}");if(s.lang==="fr")L="fr";if(s.hub&&["risk","ops"].includes(s.hub))hubKey=s.hub}catch(e){}
if(/^#?ops$/.test(location.hash))hubKey="ops";
const C={},kids={};
D.classes.forEach(c=>{C[c.id]=c;c.fam=famOf[c.mod]||"core"});
D.classes.forEach(c=>c.parents.forEach(p=>{if(C[p])(kids[p]=kids[p]||[]).push(c.id)}));
const NEW=new Set(META.newMods||[]);
const lab=c=>(L==="fr"?c.fr:c.en)||c.en;
const extLab=iri=>{if(iri.endsWith("core#Concept"))return L==="fr"?"concept de vocabulaire (SKOS)":"vocabulary concept (SKOS)";const e=D.ext[iri];return e?e.en:iri.split(/[\/#]/).pop()};
const nameOf=iri=>{const id=iri.replace(BASE,"");return C[id]?{id,t:lab(C[id])}:{id:null,t:extLab(iri)}};
const ancestors=id=>{const out=[];const st=[...(C[id]?.parents||[])];while(st.length){const p=st.shift();if(!out.includes(p)){out.push(p);if(C[p])st.push(...C[p].parents);else if(D.ext[p])st.push(...D.ext[p].parents)}}return out};
const plab=p=>(L==="fr"?p.fr:p.en)||p.en;
const fmt=n=>n.toLocaleString(L==="fr"?"fr-CA":"en");
const esc=s=>String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/"/g,"&quot;");
function save(){try{localStorage.setItem("crgo-map",JSON.stringify({lang:L,hub:hubKey}))}catch(e){}}
function facts(){const t=T[L];document.getElementById("facts").innerHTML=
 `<span><b>${fmt(D.classes.length)}</b>${t.classes}</span><span><b>${fmt(D.oprops.length)}</b>${t.rels}</span><span><b>${fmt(D.dprops.length)}</b>${t.attrs}</span><span><b>${fmt(META.scenarios)}</b>${t.scen}</span><span><b>${fmt(META.links)}</b>${t.links}</span><span><b>${fmt(META.concepts)}</b>${t.concepts}</span>`}
function chips(){const box=document.getElementById("mods");box.innerHTML="";Object.entries(FAMS).forEach(([k,m])=>{const b=document.createElement("button");b.className="chip";b.setAttribute("aria-pressed",active.has(k));b.innerHTML=`<span class="dot" style="background:var(--${k})"></span>${m[L]}`;b.onclick=()=>{active.has(k)?active.delete(k):active.add(k);if(!active.size)active.add(k);chips();cols()};box.appendChild(b)});
 document.getElementById("legend").innerHTML=Object.entries(FAMS).map(([k,m])=>`<span><span class="dot" style="background:var(--${k})"></span> <b style="color:var(--ink);font-weight:500">${m[L]}</b>: ${m.mods.map(x=>"crgo-"+x).join(", ")}</span>`).join("")}
// relation diagrams: [id,x,y]; edges [from,to,property label (en)]; bands [en,fr,x,y,anchor]
const HUBS={
 risk:{en:"Risk scenario",fr:"Scénario de risque",big:"CRGO_0000023",vb:"0 0 1100 760",
  den:"Every assessment is built around a risk scenario: what could happen, how it is assessed, what is done about it and what it leads to.",
  dfr:"Toute appréciation s’articule autour d’un scénario de risque : ce qui pourrait arriver, comment il est évalué, ce qui est fait et ce qui en découle.",
  nodes:[["CRGO_0000023",550,370],["CRGO_0000028",550,82],["CRGO_0000037",360,175],["CRGO_0000050",150,110],
   ["CRGO_0000294",150,255],["CRGO_0000014",150,360],["CRGO_0000295",150,465],["CRGO_0000001",330,590],["CRGO_0000009",130,690],
   ["CRGO_0000020",950,340],["CRGO_0000019",950,195],["REQ",760,205],["CRGO_0000022",950,475],["CRGO_0000030",900,610],
   ["CRGO_0000027",560,620],["CRGO_0000072",560,715],["CRGO_0000026",760,690]],
  edges:[["CRGO_0000028","CRGO_0000023","includes scenario"],["CRGO_0000037","CRGO_0000023","estimate of"],["CRGO_0000050","CRGO_0000037","used input"],
   ["CRGO_0000023","CRGO_0000294","has threat source description"],["CRGO_0000023","CRGO_0000014","has threat event"],["CRGO_0000023","CRGO_0000295","has vulnerability description"],
   ["CRGO_0000023","CRGO_0000001","affects asset"],["CRGO_0000001","CRGO_0000009","supports process"],["CRGO_0000023","CRGO_0000020","mitigated by"],["CRGO_0000020","CRGO_0000019","implements control"],
   ["CRGO_0000023","REQ","has relevant requirement"],["CRGO_0000023","CRGO_0000022","triggers obligation"],["CRGO_0000023","CRGO_0000030","has treatment decision"],
   ["CRGO_0000023","CRGO_0000027","has consequence"],["CRGO_0000027","CRGO_0000072","has impact dimension"],["CRGO_0000023","CRGO_0000026","has step"]],
  bands:[["HOW IT IS ASSESSED","COMMENT IL EST ÉVALUÉ",550,26,"middle"],["WHAT COULD HAPPEN","CE QUI POURRAIT ARRIVER",40,212,"start"],["WHAT IS DONE ABOUT IT","CE QUI EST FAIT",1060,145,"end"],["WHAT IT LEADS TO","CE QUI EN DÉCOULE",1060,748,"end"]]},
 ops:{en:"Governance and operations",fr:"Gouvernance et opérations",big:"CRGO_0000020",
  den:"A control measure as the organisation runs it: the policy that requires it, the assessments and audits that test it, the detection rules that implement it and the response that follows an alert. New in 0.10.0: policy versions, detection and response.",
  dfr:"Une mesure de sécurité telle que l’organisation l’applique : la politique qui l’exige, les évaluations et audits qui la testent, les règles de détection qui la mettent en œuvre et la réponse qui suit une alerte. Nouveau en 0.10.0 : versions de politiques, détection et réponse.",
  vb:"0 0 1400 800",
  nodes:[["CRGO_0000023",700,90],["CRGO_0000020",700,420],["CRGO_0000552",120,90],["CRGO_0000015",120,210],
   ["CRGO_0000886",325,250],["CRGO_0000498",325,370],["CRGO_0000347",325,540],["CRGO_0000346",325,660],["CRGO_0000541",700,600],["CRGO_0000543",450,740],
   ["CRGO_0001113",1020,90],["CRGO_0001106",1020,210],["CRGO_0001108",1020,320],["CRGO_0001101",1280,300],["CRGO_0001102",1020,440],
   ["CRGO_0000551",1280,560],["CRGO_0001112",1280,680],["CRGO_0001121",1020,640],["CRGO_0001117",1020,760],["CRGO_0001119",700,760]],
  edges:[["CRGO_0000552","CRGO_0000015","confirms incident"],["CRGO_0000015","CRGO_0000023","incident informs scenario"],["CRGO_0000023","CRGO_0000020","mitigated by"],
   ["CRGO_0000498","CRGO_0000020","statement implemented by"],["CRGO_0000498","CRGO_0000886","statement in version"],["CRGO_0000498","CRGO_0000023","intended to mitigate"],
   ["CRGO_0000347","CRGO_0000020","evaluates control measure"],["CRGO_0000346","CRGO_0000347","based on control assessment"],["CRGO_0000541","CRGO_0000020","finding on control"],["CRGO_0000543","CRGO_0000541","reports finding"],
   ["CRGO_0001102","CRGO_0000020","rule for measure"],["CRGO_0001102","CRGO_0001101","implements strategy"],["CRGO_0001106","CRGO_0000023","covers scenario"],["CRGO_0001106","CRGO_0001108","supported by test"],
   ["CRGO_0000551","CRGO_0001102","generated by rule"],["CRGO_0001112","CRGO_0000551","investigates alert"],["CRGO_0001113","CRGO_0000023","addresses scenario"],
   ["CRGO_0001121","CRGO_0001117","performs action"],["CRGO_0001121","CRGO_0001119","authorised by"]],
  bands:[["EXPERIENCE","EXPÉRIENCE",120,40,"middle"],["GOVERN, COMPLY AND AUDIT","GOUVERNER, SE CONFORMER, AUDITER",325,206,"middle"],["DETECT AND RESPOND","DÉTECTER ET RÉPONDRE",1360,40,"end"]]}};
const W=176,H=48;
function propByEn(en){return D.oprops.find(p=>p.en===en)}
function tabs(){const box=document.getElementById("tabs");box.innerHTML="";Object.entries(HUBS).forEach(([k,h])=>{const b=document.createElement("button");b.setAttribute("role","tab");b.setAttribute("aria-selected",k===hubKey);b.id="tab-"+k;b.textContent=h[L];b.onclick=()=>{hubKey=k;save();tabs();hub()};box.appendChild(b)});
 document.getElementById("l-hub").textContent=(L==="fr"?HUBS[hubKey].dfr:HUBS[hubKey].den)+" "+T[L].lhub}
function hub(){const t=T[L],G=HUBS[hubKey];const svg=document.getElementById("hub");const pos={};G.nodes.forEach(([id,x,y])=>pos[id]=[x,y]);
 svg.setAttribute("aria-label",G[L]);svg.setAttribute("viewBox",G.vb);
 let s=`<defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="var(--muted)"/></marker></defs>`;
 G.bands.forEach(([en,fr,x,y,a])=>s+=`<text class="band" x="${x}" y="${y}" text-anchor="${a}">${L==="fr"?fr:en}</text>`);
 const clip=(x1,y1,x2,y2,w,h)=>{const dx=x2-x1,dy=y2-y1;const sx=(w/2+4)/Math.abs(dx||1e-6),sy=(h/2+4)/Math.abs(dy||1e-6);const k=Math.min(sx,sy,1);return[x2-dx*k,y2-dy*k]};
 const dims=id=>id===G.big?[W+40,H+14]:[W,H];
 G.edges.forEach(([a,b,p])=>{const[x1,y1]=pos[a],[x2,y2]=pos[b];const[sx,sy]=clip(x2,y2,x1,y1,...dims(a));const[ex,ey]=clip(x1,y1,x2,y2,...dims(b));const pr=propByEn(p);const pl=pr?plab(pr):p;
  const mx=(sx+ex)/2,my=(sy+ey)/2;
  s+=`<path class="edge" data-a="${a}" data-b="${b}" d="M${sx},${sy}L${ex},${ey}" marker-end="url(#ar)"/>`;
  s+=`<g><rect x="${mx-pl.length*3.15-4}" y="${my-8}" width="${pl.length*6.3+8}" height="15" rx="3" fill="var(--surface)" opacity=".92"/><text class="elab" x="${mx}" y="${my+3}" text-anchor="middle">${esc(pl)}</text></g>`});
 G.nodes.forEach(([id,x,y])=>{let label,mod,fill,stroke,dash="";
  if(id==="REQ"){label=t.req;mod=t.reqs;fill="var(--vocab-t)";stroke="var(--vocab)";dash='stroke-dasharray="5 3"'}
  else{const c=C[id];label=lab(c);mod="crgo-"+c.mod;fill=`var(--${c.fam}-t)`;stroke=`var(--${c.fam})`}
  const big=id===G.big;const [w,h]=dims(id);
  s+=`<g class="node${sel===id?" sel":""}" data-id="${id}" tabindex="0" role="button" aria-label="${esc(label)}"><rect x="${x-w/2}" y="${y-h/2}" width="${w}" height="${h}" rx="7" fill="${fill}" stroke="${stroke}" ${dash}/>`+
   `<text class="nl" x="${x}" y="${y-(big?2:1)}" text-anchor="middle" style="${big?"font-size:16px":label.length>24?"font-size:11.5px":""}">${esc(label)}</text><text class="nm" x="${x}" y="${y+(big?18:15)}" text-anchor="middle" fill="${stroke}">${mod}</text></g>`});
 svg.innerHTML=s;
 svg.querySelectorAll(".node").forEach(n=>{const go=()=>{const id=n.dataset.id;id==="REQ"?showReq():pick(id,true)};n.onclick=go;n.onkeydown=e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();go()}};
  n.onmouseenter=()=>svg.querySelectorAll(".edge").forEach(e=>e.classList.toggle("hot",e.dataset.a===n.dataset.id||e.dataset.b===n.dataset.id));
  n.onmouseleave=()=>svg.querySelectorAll(".edge").forEach(e=>e.classList.remove("hot"))})}
function layer(){const t=T[L];document.getElementById("h-voc").textContent=t.voc;document.getElementById("l-voc").textContent=t.lvoc;
 document.getElementById("layer").innerHTML=META.vocab.map(g=>`<div class="vg"><span class="vgh">${L==="fr"?g.fr:g.en}</span>${g.items.map(([n,k,nw])=>`<span class="vchip">${esc(n)} · ${fmt(k)}${nw?`<span class="new">${META.version}</span>`:""}</span>`).join("")}</div>`).join("")}
const COLS=[["ice",{en:"Information content",fr:"Contenu informationnel"},{en:"CCO information content entity: descriptions, plans, directives, measurements, records",fr:"Entité de contenu informationnel CCO : descriptions, plans, directives, mesures, registres"}],
 ["material",{en:"Material things",fr:"Entités matérielles"},{en:"BFO material entity (and asset, which can be any entity)",fr:"Entité matérielle BFO (et actif, qui peut être toute entité)"}],
 ["dispo",{en:"Roles and dispositions",fr:"Rôles et dispositions"},{en:"BFO realizable entities",fr:"Entités réalisables BFO"}],
 ["process",{en:"Processes and acts",fr:"Processus et actes"},{en:"BFO process, including CCO planned acts",fr:"Processus BFO, y compris les actes planifiés CCO"}],
 ["concept",{en:"Value lists",fr:"Listes de valeurs"},{en:"Closed sets of SKOS concepts, pairwise disjoint",fr:"Ensembles fermés de concepts SKOS, disjoints deux à deux"}]];
const colOf=c=>({material:"material",none:"material",ice:"ice",role:"dispo",disposition:"dispo",realizable:"dispo",quality:"dispo",process:"process",concept:"concept"})[c.bucket]||"ice";
function visible(c){if(!active.has(c.fam))return false;if(!query)return true;const q=query.toLowerCase();return (c.en||"").toLowerCase().includes(q)||(c.fr||"").toLowerCase().includes(q)}
function item(id){const c=C[id];const b=document.createElement("div");
 const btn=document.createElement("button");btn.className="cls"+(sel===id?" sel":"")+(visible(c)?"":" dim");btn.dataset.id=id;btn.style.borderLeftColor=sel===id?"":`var(--${c.fam})`;
 btn.innerHTML=`<span class="dot" style="background:var(--${c.fam})"></span><span>${esc(lab(c))}${NEW.has(c.mod)?`<span class="new">${META.version}</span>`:""}</span>${c.values.length?`<span class="n">${c.values.length}</span>`:""}`;btn.onclick=()=>pick(id,false);b.appendChild(btn);
 const k=(kids[id]||[]).filter(x=>colOf(C[x])===colOf(c)).sort((a,b)=>lab(C[a]).localeCompare(lab(C[b])));
 if(k.length){const w=document.createElement("div");w.className="kids";k.forEach(x=>w.appendChild(item(x)));b.appendChild(w)}return b}
function cols(){const box=document.getElementById("cols");box.innerHTML="";
 COLS.forEach(([key,name,note])=>{const members=D.classes.filter(c=>colOf(c)===key);if(!members.length)return;
  const col=document.createElement("section");col.className="col"+(key==="ice"||key==="concept"?" wide":"");
  col.innerHTML=`<h3>${name[L]} · ${members.length}</h3><p class="bfo">${note[L]}</p>`;const tree=document.createElement("div");tree.className="tree";
  const roots=members.filter(c=>!c.parents.some(p=>C[p]&&colOf(C[p])===key));
  const groups={};
  if(key==="concept"){roots.forEach(c=>{const g=FAMS[c.fam][L];(groups[g]=groups[g]||[]).push(c.id)})}
  else roots.forEach(c=>{const g=c.parents.filter(p=>!C[p]).map(extLab)[0]||(c.parents.map(p=>C[p]?lab(C[p]):extLab(p))[0])||"entity";(groups[g]=groups[g]||[]).push(c.id)});
  Object.keys(groups).sort((a,b)=>groups[b].length-groups[a].length).forEach(g=>{const gr=document.createElement("div");gr.className="grp";gr.innerHTML=`<div class="gh">${key==="concept"?"":"⊂ "}${esc(g)}</div>`;
   groups[g].sort((a,b)=>lab(C[a]).localeCompare(lab(C[b]))).forEach(id=>gr.appendChild(item(id)));tree.appendChild(gr)});
  col.appendChild(tree);box.appendChild(col)})}
function relList(list,ownId){if(!list.length)return `<p class="chain">${T[L].none}</p>`;
 return "<ul>"+list.map(([p,other,from])=>{const o=nameOf(other);const target=o.id?`<button class="lnk" data-go="${o.id}">${esc(o.t)}</button>`:`<span>${esc(o.t)}</span>`;
  return `<li><span class="rel">${esc(plab(p))}</span> → ${target}${from&&from!==ownId&&C[from]?` <span class="inh">${T[L].inh} ${esc(lab(C[from]))}</span>`:""}</li>`}).join("")+"</ul>"}
function pick(id,scroll){if(!C[id])return;sel=id;const c=C[id],t=T[L];const anc=ancestors(id);const lineage=[id,...anc.filter(a=>C[a])];
 const out=[],inn=[];D.oprops.forEach(p=>{p.dom.forEach(dm=>{const did=dm.replace(BASE,"");if(lineage.includes(did))(p.rng.length?p.rng:["?"]).forEach(r=>out.push([p,r,did]))});
  p.rng.forEach(rg=>{const rid=rg.replace(BASE,"");if(rid===id)(p.dom.length?p.dom:[]).forEach(dm=>inn.push([p,dm,null]))})});
 const attrs=D.dprops.filter(p=>p.dom.some(dm=>lineage.includes(dm.replace(BASE,""))));
 const chain=anc.map(a=>C[a]?`<button class="lnk" data-go="${a}">${esc(lab(C[a]))}</button>`:esc(extLab(a))).join(" ⊂ ");
 const sub=(kids[id]||[]).map(k=>`<button class="lnk" data-go="${k}">${esc(lab(C[k]))}</button>`).join(", ");
 const other=L==="fr"?c.en:c.fr;
 document.getElementById("panel").innerHTML=`<span class="tag" style="background:var(--${c.fam}-t);color:var(--${c.fam})">crgo-${c.mod} · ${MODS[c.mod][L]}</span>${NEW.has(c.mod)?` <span class="new">${t.newin} ${META.version}</span>`:""}
  <h4>${esc(lab(c))}</h4><p class="alt">${esc(other||"")}</p><div class="iri"><a href="${BASE}${id}" target="_blank" rel="noopener">${BASE}${id}</a></div>
  <p class="def">${esc((L==="fr"?c.dfr:c.den)||c.den||"")}</p>
  <h5>${t.parent}</h5><p class="chain">${chain||"—"}</p>
  ${sub?`<h5>${t.sub}</h5><p class="chain">${sub}</p>`:""}
  ${c.values.length?`<h5>${t.vals} (${c.values.length})</h5><div class="vals">${c.values.map(v=>`<span>${esc(v)}</span>`).join("")}</div>`:""}
  <h5>${t.out} (${out.length})</h5>${relList(out,id)}
  <h5>${t.inn} (${inn.length})</h5>${relList(inn,id)}
  ${attrs.length?`<h5>${t.data} (${attrs.length})</h5><ul>${attrs.map(a=>`<li><span class="rel">${esc(plab(a))}</span></li>`).join("")}</ul>`:""}`;
 document.querySelectorAll("#panel [data-go]").forEach(b=>b.onclick=()=>pick(b.dataset.go,false));
 document.querySelectorAll(".cls").forEach(b=>{b.classList.toggle("sel",b.dataset.id===id);b.style.borderLeftColor=b.dataset.id===id?"":`var(--${C[b.dataset.id].fam})`});
 document.querySelectorAll("#hub .node").forEach(n=>n.classList.toggle("sel",n.dataset.id===id));
 if(scroll){const p=document.getElementById("panel");p.scrollTop=0;if(window.innerWidth<900)p.scrollIntoView({behavior:"smooth",block:"start"});else document.getElementById("h-all").scrollIntoView({behavior:"smooth",block:"start"})}}
function showReq(){sel="REQ";const t=T[L];document.getElementById("panel").innerHTML=`<span class="tag" style="background:var(--vocab-t);color:var(--vocab)">SKOS</span><h4>${t.req}</h4><p class="alt">NIST CSF 2.0 · SP 800-53 Rev. 5 · ISO/IEC 27002:2022</p><p class="def" style="margin-top:10px">${t.vocabnote}</p>`;
 document.querySelectorAll("#hub .node").forEach(n=>n.classList.toggle("sel",n.dataset.id==="REQ"));document.getElementById("h-all").scrollIntoView({behavior:"smooth"})}
function empty(){const t=T[L];document.getElementById("panel").innerHTML=`<h4>${t.pick}</h4><p class="def" style="margin-top:8px">${t.pickt}</p>`}
function texts(){const t=T[L];document.getElementById("t-map").textContent=t.map;
 document.getElementById("sub").textContent=`CRGO ${META.version} (${META.date}) · OWL 2 DL · BFO-2020 · w3id.org/crgo`;
 document.getElementById("h-hub").textContent=L==="fr"?"Comment les principales classes sont reliées":"How the main classes connect";
 document.getElementById("h-all").textContent=t.all;document.getElementById("l-all").textContent=t.lall;
 document.getElementById("q").placeholder=t.find;document.documentElement.lang=L;
 const doc="https://itriskmgr.github.io/CyberRiskGuardian-Ontology/",repo="https://github.com/ITriskMgr/CyberRiskGuardian-Ontology";
 document.getElementById("foot").innerHTML=(L==="fr"?`Généré par <code>scripts/make_map.py</code> à partir des ${Object.keys(MODS).length} modules OWL de CRGO ${META.version} et de ses vocabulaires. Documentation : <a href="${doc}">${doc.replace("https://","")}</a> · Dépôt : <a href="${repo}">${repo.replace("https://","")}</a> · Licence CC BY-NC 4.0; les identifiants des référentiels restent soumis aux conditions de leurs propriétaires (NOTICE.md).`
  :`Generated by <code>scripts/make_map.py</code> from the ${Object.keys(MODS).length} OWL modules of CRGO ${META.version} and its vocabularies. Documentation: <a href="${doc}">${doc.replace("https://","")}</a> · Repository: <a href="${repo}">${repo.replace("https://","")}</a> · Licence CC BY-NC 4.0; framework identifiers keep their owners' terms (NOTICE.md).`)}
function render(){texts();facts();chips();tabs();hub();layer();cols();if(sel==="REQ")showReq();else if(sel)pick(sel,false);else empty()}
function setLang(l){L=l;document.getElementById("l-en").setAttribute("aria-pressed",l==="en");document.getElementById("l-fr").setAttribute("aria-pressed",l==="fr");save();render()}
document.getElementById("l-en").onclick=()=>setLang("en");document.getElementById("l-fr").onclick=()=>setLang("fr");
document.getElementById("q").oninput=e=>{query=e.target.value.trim();cols();if(sel&&sel!=="REQ")pick(sel,false)};
setLang(L);pick(HUBS[hubKey].big,false);
