// RadioConnect API (requires Cloudflare D1 binding DB; not enabled in wrangler yet).
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff",...headers}});
const bytes=s=>new TextEncoder().encode(s);
const hex=a=>Array.from(new Uint8Array(a),x=>x.toString(16).padStart(2,"0")).join("");
async function digest(s){return hex(await crypto.subtle.digest("SHA-256",bytes(s)));}
async function hashPassword(password,salt){const key=await crypto.subtle.importKey("raw",bytes(password),"PBKDF2",false,["deriveBits"]);return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:bytes(salt),iterations:310000,hash:"SHA-256"},key,256));}
function equal(a,b){if(a.length!==b.length)return false;let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);return diff===0;}
function cookie(request){return request.headers.get("cookie")?.split(";").map(s=>s.trim()).find(s=>s.startsWith("rc_session="))?.slice(11)||"";}
async function identity(request,db){const token=cookie(request);if(!/^[a-f0-9]{64}$/.test(token))return null;return db.prepare("SELECT users.id,users.display_name FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at > ?").bind(await digest(token),Date.now()).first();}
const secureCookie=(token,maxAge)=>`rc_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=${maxAge}`;
export default {async fetch(request,env){
const url=new URL(request.url),path=url.pathname;
if(!path.startsWith("/api/"))return env.ASSETS.fetch(request);
if(!env.DB)return json({error:"Database is nog niet gekoppeld"},503);
if(!["GET","POST"].includes(request.method))return json({error:"Methode niet toegestaan"},405);
if(request.method==="POST"&&(request.headers.get("origin")!==url.origin||!request.headers.get("content-type")?.startsWith("application/json")))return json({error:"Ongeldige aanvraag"},403);
let body={};if(request.method==="POST"){if(Number(request.headers.get("content-length")||0)>4096)return json({error:"Aanvraag te groot"},413);try{body=await request.json();if(JSON.stringify(body).length>4096)throw Error();}catch{return json({error:"Ongeldige JSON"},400);}}
try{
if(path==="/api/crypto-check"&&request.method==="GET"){
// Isolated password-hashing self-test: no credentials, user data or D1 writes.
try{
const salt="radioconnect-self-test-v1";
const first=await hashPassword("RadioConnect-TestPassword-2026!",salt);
const second=await hashPassword("RadioConnect-TestPassword-2026!",salt);
const different=await hashPassword("RadioConnect-TestPassword-2026?",salt);
const ok=/^[a-f0-9]{64}$/.test(first)&&equal(first,second)&&!equal(first,different);
return json({status:ok?"ok":"failed",checks:{pbkdf2:ok?"ok":"failed",deterministic:equal(first,second),password_separation:!equal(first,different)},database_untouched:true},ok?200:503);
}catch(error){console.error("Crypto self-test failed",error);return json({status:"failed",checks:{pbkdf2:"failed"},database_untouched:true},503);}
}
if(path==="/api/health"&&request.method==="GET"){
const checks={binding:"connected",database:"pending",users:"pending",credentials:"pending",sessions:"pending"};
const run=async(label,sql)=>{try{await env.DB.prepare(sql).first();checks[label]="ok";}catch(err){const message=String(err?.message||err||"");checks[label]=/no such table/i.test(message)?"missing_table":/limit|quota|exceeded/i.test(message)?"quota_or_limit":"query_failed";console.error("Health check "+label,err);}};
await run("database","SELECT 1 AS ok");
await run("users","SELECT id FROM users LIMIT 1");
await run("credentials","SELECT user_id FROM credentials LIMIT 1");
await run("sessions","SELECT token_hash FROM sessions LIMIT 1");
const ok=Object.values(checks).every(v=>v==="ok"||v==="connected");
return json({status:ok?"ok":"degraded",checks},ok?200:503);
}
if(path==="/api/register"&&request.method==="POST"){
const email=String(body.email||"").trim().toLowerCase(),password=String(body.password||""),name=String(body.name||"").trim();
if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254||password.length<12||password.length>128||name.length<2||name.length>80)return json({error:"Vul een geldige naam, e-mail en wachtwoord (minimaal 12 tekens) in"},400);
const salt=crypto.randomUUID(),hash=await hashPassword(password,salt);
try{await env.DB.prepare("INSERT INTO users (id,auth_subject,display_name) VALUES (?,?,?)").bind(crypto.randomUUID(),email,name).run();await env.DB.prepare("INSERT INTO credentials (user_id,salt,password_hash) SELECT id,?,? FROM users WHERE auth_subject=?").bind(salt,hash,email).run();}catch{return json({error:"Registratie niet mogelijk; e-mailadres mogelijk al in gebruik"},409);}
return json({ok:true},201);
}
if(path==="/api/login"&&request.method==="POST"){
const email=String(body.email||"").trim().toLowerCase(),password=String(body.password||"");
if(email.length>254||password.length>128)return json({error:"Ongeldige inloggegevens"},401);
const rateKey=await digest("login:"+email+":"+ (request.headers.get("cf-connecting-ip")||"unknown"));
const rate=await env.DB.prepare("SELECT count,window_start FROM login_attempts WHERE key=?").bind(rateKey).first();
if(rate&&Date.now()-rate.window_start<900000&&rate.count>=8)return json({error:"Te veel pogingen; probeer later opnieuw"},429);
const user=await env.DB.prepare("SELECT users.id,credentials.salt,credentials.password_hash FROM users JOIN credentials ON users.id=credentials.user_id WHERE users.auth_subject=?").bind(email).first();
const computed=await hashPassword(password,user?.salt||"fallback-salt");
if(!user||!equal(computed,user.password_hash)){
await env.DB.prepare("INSERT INTO login_attempts (key,count,window_start) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN ?-window_start>=900000 THEN 1 ELSE count+1 END,window_start=CASE WHEN ?-window_start>=900000 THEN ? ELSE window_start END").bind(rateKey,Date.now(),Date.now(),Date.now(),Date.now()).run();
return json({error:"Ongeldige inloggegevens"},401);
}
await env.DB.prepare("DELETE FROM login_attempts WHERE key=?").bind(rateKey).run();
const token=hex(crypto.getRandomValues(new Uint8Array(32))),expiry=Date.now()+7*86400000;
await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)").bind(await digest(token),user.id,expiry).run();
return json({ok:true},200,{"set-cookie":secureCookie(token,604800)});
}
if(path==="/api/me"&&request.method==="GET"){const user=await identity(request,env.DB);return user?json({user}):json({user:null},401);}
if(path==="/api/logout"&&request.method==="POST"){const token=cookie(request);if(/^[a-f0-9]{64}$/.test(token))await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();return json({ok:true},200,{"set-cookie":secureCookie("",0)});}
if(path==="/api/stations"&&request.method==="POST"){
const user=await identity(request,env.DB);if(!user)return json({error:"Log eerst in"},401);
const name=String(body.name||"").trim();if(name.length<2||name.length>80)return json({error:"Ongeldige stationsnaam"},400);
const id=crypto.randomUUID();await env.DB.batch([
env.DB.prepare("INSERT INTO stations(id,name,visibility,owner_user_id) VALUES (?,?,'private',?)").bind(id,name,user.id),
env.DB.prepare("INSERT INTO station_members(station_id,user_id,role) VALUES (?,?,'owner')").bind(id,user.id),
env.DB.prepare("INSERT INTO rooms(id,station_id,name,visibility) VALUES (?,?,'algemeen','members')").bind(crypto.randomUUID(),id)
]);return json({id,name,visibility:"private"},201);
}
if(path==="/api/stations"&&request.method==="GET"){
const user=await identity(request,env.DB);if(!user)return json({error:"Log eerst in"},401);
const rows=await env.DB.prepare("SELECT s.id,s.name,s.visibility,m.role FROM stations s JOIN station_members m ON m.station_id=s.id WHERE m.user_id=? ORDER BY s.created_at DESC").bind(user.id).all();return json({stations:rows.results});
}
return json({error:"Niet gevonden"},404);
}catch(error){console.error("API error",error);const detail=String(error?.message||error||"");if(/exceeded.*(?:row read|daily|limit)|free tier daily row read|D1_ERROR.*limit/i.test(detail))return json({error:"Cloudflare D1 heeft de dagelijkse leeslimiet bereikt. Probeer na 00:00 UTC opnieuw of verhoog de D1-limiet via je Cloudflare-abonnement.",code:"D1_DAILY_LIMIT"},503);if(/no such table/i.test(detail))return json({error:"De database mist een benodigde tabel. Controleer de database-migraties.",code:"DB_SCHEMA_MISSING"},503);return json({error:"Interne serverfout. Controleer de Worker-logs in Cloudflare Observability.",code:"SERVER_ERROR"},500);}
}};