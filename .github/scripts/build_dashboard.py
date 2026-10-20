
#!/usr/bin/env python3
"""Build a self-contained static dashboard from the metrics-data CSV files."""
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(os.environ.get("METRICS_DIR", "metrics-data/metrics"))
OUTPUT = Path(os.environ.get("DASHBOARD_DIR", "site")) / "index.html"


def read_csv(name):
    """Read one metrics CSV, treating a missing file as an empty dataset."""
    path = DATA_DIR / name
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def main():
    data = {
        "batch": read_csv("batch_fuzzers.csv"),
        "corpus": read_csv("corpus_snapshots.csv"),
        "coverage": read_csv("coverage_snapshots.csv"),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # A '<' can start an HTML closing-script tag even inside a JavaScript string.
    # Encoding it as a JSON Unicode escape prevents the HTML parser from ending
    # this script early; JSON parsing in the browser restores the original value.
    payload = json.dumps(data, separators=(",", ":")).replace("<", "\\u003c")

    template = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TFW fuzzing metrics</title>
<style>
:root{color-scheme:light dark;--bg:#f5f7fa;--card:#fff;--ink:#182230;--muted:#5e6b7b;--line:#dce3eb;--accent:#1769aa;--accent2:#e07a25}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{background:#172b4d;color:white;padding:2rem max(1rem,calc((100% - 1120px)/2))}
header h1{margin:0;font-size:clamp(1.7rem,4vw,2.5rem)}
header p{margin:.4rem 0 0;color:#d8e4f4}
.wrap{max-width:1120px;margin:auto;padding:1.25rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:1rem}
.card,section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem;box-shadow:0 2px 7px #172b4d0b}
.kpi{font-size:1.8rem;font-weight:750;line-height:1.2}
.muted,small{color:var(--muted)}
section{margin-top:1rem}
h2{font-size:1.25rem;margin:0 0 .65rem}
label{display:block;font-weight:650;margin:.4rem 0}
select{font:inherit;padding:.5rem;max-width:100%;border:1px solid var(--line);border-radius:7px;background:var(--card);color:var(--ink)}
.chart{width:100%;height:auto;display:block;min-height:180px}
.legend{display:flex;gap:1rem;flex-wrap:wrap;font-size:.9rem}
.dot{display:inline-block;width:.7rem;height:.7rem;border-radius:50%;margin-right:.3rem}
.note{font-size:.9rem;color:var(--muted)}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:.5rem;border-bottom:1px solid var(--line)}
th{color:var(--muted)}
.tablewrap{overflow-x:auto}
footer{padding:2rem 1rem;text-align:center;color:var(--muted)}
a{color:var(--accent)}
@media(prefers-color-scheme:dark){:root{--bg:#101722;--card:#182230;--ink:#e8edf4;--muted:#a5b2c2;--line:#344153;--accent:#79baff;--accent2:#ffb36e}}
</style>
</head>
<body>
<header>
  <h1>TFW fuzzing metrics</h1>
  <p>Historical ClusterFuzzLite performance, persistent corpus, and JaCoCo source coverage.</p>
</header>
<main class="wrap">
  <div class="cards" id="kpis"></div>
  <section>
    <h2>Fuzzer history</h2>
    <label for="fuzzer">Choose a fuzzer</label>
    <select id="fuzzer"></select>
    <p class="note">Each point is a successful batch run. <b>cov</b> and <b>ft</b> are libFuzzer counters, not source-coverage percentages.</p>
    <div class="legend"><span><i class="dot" style="background:#1769aa"></i>cov</span><span><i class="dot" style="background:#e07a25"></i>ft</span></div>
    <div id="fuzzer-chart"></div>
    <h3>Execution throughput</h3>
    <div id="throughput-chart"></div>
  </section>
  <div class="two">
    <section>
      <h2>JaCoCo source coverage</h2>
      <div class="legend" aria-label="Coverage chart legend">
        <span><i class="dot" style="background:#1769aa"></i>Line coverage %</span>
        <span><i class="dot" style="background:#e07a25"></i>Branch coverage %</span>
      </div>
      <div id="coverage-chart"></div>
      <p class="note">Source-code line and branch coverage from the published JaCoCo report.</p>
    </section>
    <section>
      <h2>Persistent corpus size</h2>
      <label for="corpus-fuzzer">Choose a fuzzer</label>
      <select id="corpus-fuzzer"></select>
      <div id="corpus-chart"></div>
      <p class="note">Corpus observations are collected independently of batch runs and are tied to a tfw-fuzzing commit.</p>
    </section>
  </div>
  <section>
    <h2>Latest fuzzer results</h2>
    <div class="tablewrap" id="latest-table"></div>
  </section>
  <p class="note" id="updated"></p>
</main>
<footer>Generated from the <a href="https://github.com/tfw-org/tfw-metrics">TFW metrics repository</a>. Collection history is stored separately on the <code>metrics-data</code> branch.</footer>
<script>
const DATA=__DATA__;
const $=id=>document.getElementById(id);

// Empty or absent measurements are unavailable, not numeric zero.
const num=v=>{
  if(v==null || String(v).trim()==='') return null;
  const n=Number(v);
  return Number.isFinite(n)?n:null;
};
const fmt=n=>n==null?'—':new Intl.NumberFormat().format(n);
const date=s=>s?new Date(s).toLocaleString():'';

const observation=(timestamp,y)=>({
  x:Date.parse(timestamp),
  label:date(timestamp),
  y
});

// Escape text inserted into HTML markup, such as a fuzzer name in a table.
const esc=v=>String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

function el(tag,attrs={},text=''){
  const e=document.createElementNS('http://www.w3.org/2000/svg',tag);
  for(const [k,v] of Object.entries(attrs)) e.setAttribute(k,v);
  if(text!=='') e.textContent=text;
  return e;
}

function svgChart(series,opts={}){
  const w=900,h=280,L=58,R=20,T=18,B=42,iw=w-L-R,ih=h-T-B;
  const points=series.flatMap(s=>s.values.map(p=>p.y).filter(v=>v!=null));
  if(!points.length) return '<p class="muted">Not enough observations yet to draw a chart.</p>';

  // Find bounds iteratively so large histories cannot exceed the argument limit.
  // The default minimum includes zero, while the default maximum uses observed data.
  let min=opts.min??0;
  let max=opts.max??-Infinity;
  for(const point of points){
    if(opts.min==null) min=Math.min(min,point);
    if(opts.max==null) max=Math.max(max,point);
  }
  if(max===min) max=min+1;

  // Use elapsed time for the horizontal axis instead of evenly spaced array indices.
  const times=series.flatMap(ser=>
    ser.values.map(p=>p.x).filter(Number.isFinite)
  );
  if(!times.length) {
    return '<p class="muted">Not enough observations yet to draw a chart.</p>';
  }

  let minX=Infinity;
  let maxX=-Infinity;
  for(const timestamp of times) {
    minX=Math.min(minX,timestamp);
    maxX=Math.max(maxX,timestamp);
  }

  const x=timestamp=>
    L+(maxX===minX
      ? iw/2
      : (timestamp-minX)/(maxX-minX)*iw);
  const y=v=>T+ih-(v-min)/(max-min)*ih;
  const s=el('svg',{viewBox:`0 0 ${w} ${h}`,class:'chart',role:'img','aria-label':opts.label||'Historical metrics chart'});

  for(let i=0;i<5;i++){
    const val=min+(max-min)*i/4,yy=y(val);
    s.append(el('line',{x1:L,y1:yy,x2:w-R,y2:yy,stroke:'var(--line)','stroke-width':1}));
    s.append(el('text',{x:L-8,y:yy+4,'text-anchor':'end',fill:'var(--muted)','font-size':11},fmt(Math.round(val))));
  }

  series.forEach(ser=>{
    let d='';

    // A missing observation breaks the line. Do not connect measurements
    // across a gap, since doing so would imply data exists between them.
    const appendPath=path=>{
      if(path) s.append(el('path',{d:path,fill:'none',stroke:ser.color,
        'stroke-width':2.5,'stroke-linejoin':'round'}));
    };

    ser.values.forEach(p=>{
      if(p.y==null || !Number.isFinite(p.x)) {
        appendPath(d);
        d='';
        return;
      }
      d+=(d?' L':'M')+x(p.x)+' '+y(p.y);
    });
    appendPath(d);

    // Keep the individual observation markers, including those adjacent to gaps.
    ser.values.forEach(p=>{
      if(p.y!=null && Number.isFinite(p.x)) {
        const c=el('circle',{
          cx:x(p.x),
          cy:y(p.y),
          r:3.5,
          fill:ser.color
        });
        c.append(el('title',{},`${p.label}: ${fmt(p.y)}`));
        s.append(c);
      }
    });
  });

  // Show up to three date labels from the first series.
  const vals=series[0].values;
  [0,Math.floor((vals.length-1)/2),vals.length-1]
    .filter((v,i,a)=>a.indexOf(v)===i&&v>=0)
    .forEach(i=>{
      const p=vals[i];
      if(p && Number.isFinite(p.x)) {
        s.append(el('text',{x:x(p.x),y:h-12,
          'text-anchor':i===0?'start':
            i===vals.length-1?'end':'middle',
          fill:'var(--muted)','font-size':11},p.label));
      }
    });
  return s.outerHTML;
}

function chartInto(id,series,opts){$(id).innerHTML=svgChart(series,opts);}

const batch=DATA.batch.slice().sort((a,b)=>a.completed_at.localeCompare(b.completed_at));
const corpus=DATA.corpus.slice().sort((a,b)=>a.observed_at.localeCompare(b.observed_at));
const coverage=DATA.coverage.slice().sort((a,b)=>a.observed_at.localeCompare(b.observed_at));
const latestByFuzzer=new Map();
batch.forEach(r=>{
  const prev=latestByFuzzer.get(r.fuzzer);
  if(!prev||r.completed_at>prev.completed_at) latestByFuzzer.set(r.fuzzer,r);
});
const latestBatch=batch.length?batch.reduce((a,b)=>a.completed_at>b.completed_at?a:b):null;
const latestCov=coverage[coverage.length-1];
const lineCoverage=latestCov?num(latestCov.line_coverage_percent):null;

$('kpis').innerHTML=[
  ['Fuzzers tracked',new Set(batch.map(r=>r.fuzzer)).size],
  ['Successful run/fuzzer samples',batch.length],
  ['Latest batch run',latestBatch?date(latestBatch.completed_at):'No data'],
  ['Line coverage',lineCoverage==null?'No data':`${lineCoverage}%`],
  ['Corpus snapshots',corpus.length]
].map(([label,value])=>`<div class="card"><div class="muted">${esc(label)}</div><div class="kpi">${esc(value)}</div></div>`).join('');

const fuzzers=[...new Set(batch.map(r=>r.fuzzer))].sort();
function fillSelect(id,values){
  $(id).replaceChildren(...values.map(v=>{
    const o=document.createElement('option');o.value=v;o.textContent=v;return o;
  }));
}
fillSelect('fuzzer',fuzzers);
const corpusFuzzers=[...new Set(corpus.map(r=>r.fuzzer))].sort();
fillSelect('corpus-fuzzer',corpusFuzzers);

function drawFuzzer(){
  const name=$('fuzzer').value,rows=batch.filter(r=>r.fuzzer===name);
  chartInto('fuzzer-chart',[
    {name:'cov',color:'#1769aa',values:rows.map(r=>observation(r.completed_at,num(r.cov)))},
    {name:'ft',color:'#e07a25',values:rows.map(r=>observation(r.completed_at,num(r.ft)))}
  ],{label:`Historical libFuzzer counters for ${name}`});
  chartInto('throughput-chart',[
    {name:'exec/s',color:'#2c8c62',values:rows.map(r=>observation(r.completed_at,num(r.average_exec_per_sec)))}
  ],{label:`Execution throughput for ${name}`,min:0});
}

function drawLatestTable(){
  // This summary is independent of the selected history-chart fuzzer.
  const rows=[...latestByFuzzer.values()]
    .sort((a,b)=>a.fuzzer.localeCompare(b.fuzzer));

  if(!rows.length){
    $('latest-table').innerHTML='<p>No fuzzer data yet.</p>';
    return;
  }

  const headers=[
    'Fuzzer','Run date','cov','ft','Executions','Exec/sec',
    'Active corpus units','Active corpus bytes','New units'
  ];
  const head='<thead><tr>'+
    headers.map(h=>`<th>${esc(h)}</th>`).join('')+
    '</tr></thead>';
  const body='<tbody>'+rows.map(r=>'<tr>'+
    [
      r.fuzzer,
      date(r.completed_at),
      fmt(num(r.cov)),
      fmt(num(r.ft)),
      fmt(num(r.executions)),
      fmt(num(r.average_exec_per_sec)),
      fmt(num(r.active_corpus_units)),
      fmt(num(r.active_corpus_bytes)),
      fmt(num(r.new_units_added))
    ].map(v=>`<td>${esc(v)}</td>`).join('')+
    '</tr>').join('')+'</tbody>';

  $('latest-table').innerHTML=`<table>${head}${body}</table>`;
}

function drawCorpus(){
  const name=$('corpus-fuzzer').value,rows=corpus.filter(r=>r.fuzzer===name);
  chartInto('corpus-chart',[
    {name:'Persistent corpus bytes',color:'#1769aa',
     values:rows.map(r=>observation(r.observed_at,num(r.persistent_corpus_bytes)))}
  ],{label:`Persistent corpus size for ${name}`,min:0});
}

chartInto('coverage-chart',[
  {name:'Line coverage %',color:'#1769aa',
   values:coverage.map(r=>observation(r.observed_at,num(r.line_coverage_percent)))},
  {name:'Branch coverage %',color:'#e07a25',
   values:coverage.map(r=>observation(r.observed_at,num(r.branch_coverage_percent)))}
],{label:'JaCoCo line and branch source coverage percentages over time',min:0,max:100});

$('fuzzer').addEventListener('change',drawFuzzer);
$('corpus-fuzzer').addEventListener('change',drawCorpus);

// Always render the panels so empty datasets display their fallback messages.
drawFuzzer();
drawCorpus();
drawLatestTable();

$('updated').textContent=`Dashboard generated ${date(DATA.generatedAt)}. Coverage observations: ${coverage.length}; corpus observations: ${corpus.length}.`;
</script>
</body>
</html>"""
    OUTPUT.write_text(template.replace("__DATA__", payload), encoding="utf-8")
    print(f"Wrote {OUTPUT} ({OUTPUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
