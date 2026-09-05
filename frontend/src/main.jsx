import React, {useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

function App(){
 const [key,setKey]=useState(''), [alerts,setAlerts]=useState([]), [stats,setStats]=useState(null);
 const [error,setError]=useState(''), [busy,setBusy]=useState(false), [selected,setSelected]=useState(null);
 const [summary,setSummary]=useState(null), [summarizing,setSummarizing]=useState(false), [filter,setFilter]=useState('all');
 async function api(path,method='GET'){
  const r=await fetch('/api/'+path,{method,headers:{'X-API-Key':key}});
  if(!r.ok) throw new Error(r.status===401?'The API key was not accepted.': 'Request failed ('+r.status+'). Check the API and try again.');
  return r.json();
 }
 async function refresh(e){
  e?.preventDefault(); setBusy(true);setError('');setSelected(null);setSummary(null);
  try {const [s,a]=await Promise.all([api('stats'),api('alerts')]);setStats(s);setAlerts(a);}
  catch(e){setError(e.message);setStats(null);setAlerts([]);}
  finally {setBusy(false);}
 }
 async function summarize(){
  setSummarizing(true);setSummary(null);
  try {setSummary(await api('alerts/'+encodeURIComponent(selected.event.event_id)+'/summary','POST'));}
  catch(e){setSummary({source:'error',summary:e.message});}
  finally {setSummarizing(false);}
 }
 const visible=alerts.filter(a=>filter==='all'||a.severity>=75);
 return <div className="shell">
  <aside><div className="brand"><span className="mark">C</span> CloudSentinel</div><div className="nav active">◈ &nbsp; Detection overview</div><div className="aside-bottom">SECURITY OPERATIONS<br/><strong>Portfolio edition · v0.1</strong><p>Synthetic ML baseline<br/>Analyst review required</p></div></aside>
  <main><header><div><div className="eyebrow">CLOUD SECURITY / DETECTION</div><h1>Detection overview</h1><p>Investigate unusual activity across cloud identities.</p></div><span className="badge">{stats?'API connected':'Awaiting connection'}</span></header>
   <form onSubmit={refresh} className="connect"><label htmlFor="key">API key</label><input id="key" type="password" disabled={busy||summarizing} value={key} autoComplete="off" onChange={e=>{setKey(e.target.value);setStats(null);setAlerts([]);setSelected(null);setSummary(null);}} placeholder="Enter your API key" required/><button disabled={busy||summarizing}>{busy?'Loading…':stats?'Refresh events':'Connect'}</button><span>Kept in memory for this session.</span></form>
   {error&&<div role="alert" className="error">{error}</div>}
   <section className="stats" aria-label="Detection statistics">{[['Events ingested',stats?.events],['Events with findings',stats?.alerts],['High severity',stats?.high_severity]].map(([label,n])=><article key={label}><span>{label}</span><strong>{n??'—'}</strong><small>{label==='High severity'?'Rule severity ≥ 75':'All stored events'}</small></article>)}</section>
   <div className="workspace"><section className="feed"><div className="section-head"><div><h2>Alert queue</h2><p>Latest 100 events with findings</p></div><select aria-label="Filter severity" value={filter} onChange={e=>setFilter(e.target.value)}><option value="all">All severities</option><option value="high">High severity</option></select></div>
    {!visible.length?<div className="empty"><span>◈</span><h3>{stats?'No matching alerts':'Connect to inspect activity'}</h3><p>{stats?'Ingest logs or run the synthetic demo to populate the queue.':'Enter the key configured on your API to load security findings.'}</p></div>:<div className="table-wrap"><table><thead><tr><th>Finding / identity</th><th>Severity</th><th>Anomaly</th><th>Time (UTC)</th></tr></thead><tbody>{visible.map(a=><tr key={a.event.event_id} className={selected?.event.event_id===a.event.event_id?'selected':''}><td><button className="row-button" disabled={summarizing} onClick={()=>{setSelected(a);setSummary(null);}}>{a.findings.reduce((x,y)=>x.severity>y.severity?x:y).category}</button><small>{a.event.principal}</small></td><td><span className={'severity '+(a.severity>=75?'high':'medium')}>{a.severity}</span></td><td>{a.anomaly_score}<small>ranking / 100</small></td><td>{new Date(a.event.timestamp).toISOString().slice(0,16).replace('T',' ')}</td></tr>)}</tbody></table></div>}
   </section><section className="detail"><div className="eyebrow">INVESTIGATION</div><h2>{selected?'Finding details':'Select an alert'}</h2>{!selected?<p>Open a finding to review its evidence, threat mapping, and incident summary.</p>:<><dl><dt>Action</dt><dd>{selected.event.action}</dd><dt>Principal</dt><dd>{selected.event.principal}</dd><dt>Source</dt><dd>{selected.event.source_ip}</dd></dl>{selected.findings.map((f,i)=><article className="finding" key={i}><strong>{f.category}</strong><span>{f.technique||'No technique assigned'}</span><p>{f.evidence}</p></article>)}<button onClick={summarize} disabled={summarizing}>{summarizing?'Summarizing…':'Summarize incident'}</button>{summary&&<div aria-live="polite" className="summary"><div className="eyebrow">{summary.source.replaceAll('_',' ')}</div><p>{summary.summary}</p></div>}</>}</section></div>
   <footer>Model: {stats?.model||'synthetic-iforest-v1'} · Scores rank anomalies; they are not probabilities of compromise. <a href="/docs" target="_blank" rel="noreferrer">API documentation ↗</a></footer>
  </main></div>;
}
createRoot(document.getElementById('root')).render(<App/>);
