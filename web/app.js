const $=id=>document.getElementById(id);
const patterns={
credential:/password|passcode|credential|login|sign[ -]?in|otp|one[- ]time password|verification code/ig,
personal:/date of birth|dob|address|phone number|social security|aadhaar|pan card|identity|id number|personal information/ig,
threat:/suspend|terminate|close your account|legal action|penalty|arrest|blocked|locked|warning/ig,
action:/click|open|download|reply|call|confirm|verify|update|submit|pay|send/ig,
urgency:/urgent|immediately|asap|right now|act now|last chance|expires|deadline|within \d+ hours?/ig,
suspicious:/login|sign[ -]?in|verify|verification|account|password|credential|bank|payment|invoice|refund|otp|security|suspend|locked|click|update|confirm/ig};
const urlRe=/(?:https?:\/\/|www\.)[^\s<>"']+|\b(?:[a-z0-9-]+\.)+(?:com|org|net|edu|gov|io|co|uk|in|xyz|me|app|site)\b/ig;
const count=(re,t)=>(t.match(re)||[]).length;
function analyze(t){
 const urls=t.match(urlRe)||[]; let score=0,signals=[];
 const phishing=Math.min(99,25+count(patterns.suspicious,t)*5+count(patterns.urgency,t)*7+urls.length*5);
 if(phishing>=90){score+=5;signals.push("High phishing-language signal")}else if(phishing>=70){score+=4;signals.push("Elevated phishing-language signal")}else if(phishing>=50){score+=2;signals.push("Some phishing-language indicators")}else if(phishing>=30)score++;
 if(count(patterns.credential,t)){score+=3;signals.push("Credential or OTP request")}
 if(count(patterns.personal,t)){score+=2;signals.push("Personal-information request")}
 if(count(patterns.threat,t)){score++;signals.push("Threat or pressure language")}
 if(count(patterns.action,t)){score++;signals.push("Action requested from recipient")}
 const s=count(patterns.suspicious,t),u=count(patterns.urgency,t); if(s>=8)score+=2;else if(s>=4)score++;if(u>=4)score+=2;else if(u>=2)score++;
 if(urls.length>=3){score++;signals.push("Multiple URLs detected")} if(urls.length)signals.push(urls.length+" URL"+(urls.length>1?"s":"")+" detected");
 return{label:score>=10?"HIGH":score>=5?"MEDIUM":"LOW",score,phishing,urls,signals:[...new Set(signals)]};
}
$("analyze").onclick=()=>{
 const t=$("message").value.trim();if(!t){$("result").innerHTML='<div class="empty">Paste a message first.</div>';return}
 const r=analyze(t);$("result").innerHTML='<div class="risk"><span class="badge '+r.label.toLowerCase()+'">'+r.label+' RISK</span><span class="muted">Risk score</span><span class="score">'+r.score+'</span></div><p class="muted">Estimated phishing-language signal: '+r.phishing+'%</p><h3>Why it was flagged</h3><ul class="signals">'+(r.signals.length?r.signals.map(x=>'<li>'+x+'</li>').join(""):'<li>No strong risk signal detected.</li>')+'</ul><p class="muted" style="margin-top:22px">This page is a lightweight client-side demo. The full trained ML pipeline remains in the Streamlit demo.</p>';
};