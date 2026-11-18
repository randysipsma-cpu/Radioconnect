// RadioConnect API (requires Cloudflare D1 binding DB; not enabled in wrangler yet).
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff",...headers}});
const bytes=s=>new TextEncoder().encode(s);
const hex=a=>Array.from(new Uint8Array(a),x=>x.toString(16).padStart(2,"0")).join("");
async function digest(s){return hex(await crypto.subtle.digest("SHA-256",bytes(s)));}
async function hashPassword(password,salt){const key=await crypto.subtle.importKey("raw",bytes(password),"PBKDF2",false,["deriveBits"]);return hex(await crypto.subtle.deriveBits({name:"PBKDF2",salt:bytes(salt),iterations:100000,hash:"SHA-256"},key,256));}
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
}catch(error){console.error("Crypto self-test failed",error);return json({status:"failed",checks:{pbkdf2:"failed"},diagnostic:{name:String(error?.name||"UnknownError"),message:String(error?.message||"No details").slice(0,180)},database_untouched:true},503);}
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
if(/^\/api\/stations\/[a-f0-9-]{36}$/.test(path)&&request.method==="POST"){
const user=await identity(request,env.DB);if(!user)return json({error:"Log eerst in"},401);
const id=path.split("/")[3],name=String(body.name||"").trim();
if(name.length<2||name.length>80)return json({error:"Stationsnaam moet 2 tot 80 tekens bevatten"},400);
const result=await env.DB.prepare("UPDATE stations SET name=? WHERE id=? AND owner_user_id=?").bind(name,id,user.id).run();
if(!result.meta?.changes)return json({error:"Station niet gevonden of geen eigenaarrechten"},403);
return json({ok:true,id,name});
}
const roomSocket=path.match(/^\/api\/rooms\/([a-f0-9-]{36})\/live$/);
if(roomSocket&&request.method==="GET"){
if(request.headers.get("upgrade")?.toLowerCase()!=="websocket")return json({error:"WebSocket vereist"},426);
if(request.headers.get("origin")!==url.origin)return json({error:"Ongeldige herkomst"},403);
const user=await identity(request,env.DB);if(!user)return json({error:"Log eerst in"},401);
const room=await env.DB.prepare("SELECT r.id,r.visibility,m.role FROM rooms r JOIN station_members m ON m.station_id=r.station_id AND m.user_id=? WHERE r.id=?").bind(user.id,roomSocket[1]).first();
if(!room||room.visibility==="management"&&!["owner","admin"].includes(room.role))return json({error:"Geen toegang"},403);
if(!env.CHAT_ROOM)return json({error:"Realtime chat is nog niet geconfigureerd"},503);
const stub=env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName(room.id));
return stub.fetch(new Request("https://internal/connect",{headers:{"Upgrade":"websocket","X-RC-User":user.id,"X-RC-Name":encodeURIComponent(user.display_name)}}));
}
// Station-scoped private chat: every request checks membership server-side.
const stationRooms=path.match(/^\/api\/stations\/([a-f0-9-]{36})\/rooms$/);
if(stationRooms&&request.method==="GET"){
const user=await identity(request,env.DB);if(!user)return json({error:"Log eerst in"},401);
const membership=await env.DB.prepare("SELECT role FROM station_members WHERE station_id=? AND user_id=?").bind(stationRooms[1],user.id).first();
if(!membership)return json({error:"Geen toegang tot dit privéradiostation"},403);
const rooms=await env.DB.prepare("SELECT id,name,visibility FROM rooms WHERE station_id=? ORDER BY name LIMIT 100").bind(stationRooms[1]).all();
return json({rooms:rooms.results});
}
const roomMessages=path.match(/^\/api\/rooms\/([a-f0-9-]{36})\/messages$/);
if(roomMessages){
const user=await identity(request,env.DB);if(!user)return json({error:"Log eerst in"},401);
const room=await env.DB.prepare("SELECT r.id,r.station_id,r.visibility,m.role FROM rooms r JOIN station_members m ON m.station_id=r.station_id AND m.user_id=? WHERE r.id=?").bind(user.id,roomMessages[1]).first();
if(!room)return json({error:"Geen toegang tot deze privéroom"},403);
if(room.visibility==="management"&&!["owner","admin"].includes(room.role))return json({error:"Geen toegang tot deze beheerroom"},403);
if(request.method==="POST"){
const message=String(body.message||"").trim();
if(message.length<1||message.length>2000)return json({error:"Bericht moet 1 tot 2000 tekens bevatten"},400);
const id=crypto.randomUUID(),created=Date.now();
await env.DB.prepare("INSERT INTO chat_messages(id,room_id,user_id,body,created_at) VALUES(?,?,?,?,?)").bind(id,room.id,user.id,message,created).run();
if(env.CHAT_ROOM){try{const stub=env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName(room.id));await stub.fetch("https://internal/broadcast",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:"message",message:{id,body:message,created_at:created,display_name:user.display_name}})});}catch(error){console.error("Chat realtime broadcast failed",error);}}

return json({id,created_at:created},201);
}
const before=Number(url.searchParams.get("before")||0);
if(before&&!Number.isSafeInteger(before))return json({error:"Ongeldige paginering"},400);
const rows=await env.DB.prepare("SELECT c.id,c.body,c.created_at,u.display_name FROM chat_messages c JOIN users u ON u.id=c.user_id WHERE c.room_id=? AND (?=0 OR c.created_at<?) ORDER BY c.created_at DESC LIMIT 50").bind(room.id,before,before).all();
return json({messages:rows.results.reverse()});
}
if(path==="/api/stations"&&request.method==="GET"){
const user=await identity(request,env.DB);if(!user)return json({error:"Log eerst in"},401);
const rows=await env.DB.prepare("SELECT s.id,s.name,s.visibility,m.role FROM stations s JOIN station_members m ON m.station_id=s.id WHERE m.user_id=? ORDER BY s.created_at DESC").bind(user.id).all();return json({stations:rows.results});
}
return json({error:"Niet gevonden"},404);
}catch(error){console.error("API error",error);const detail=String(error?.message||error||"");if(/exceeded.*(?:row read|daily|limit)|free tier daily row read|D1_ERROR.*limit/i.test(detail))return json({error:"Cloudflare D1 heeft de dagelijkse leeslimiet bereikt. Probeer na 00:00 UTC opnieuw of verhoog de D1-limiet via je Cloudflare-abonnement.",code:"D1_DAILY_LIMIT"},503);if(/no such table/i.test(detail))return json({error:"De database mist een benodigde tabel. Controleer de database-migraties.",code:"DB_SCHEMA_MISSING"},503);return json({error:"Interne serverfout. Controleer de Worker-logs in Cloudflare Observability.",code:"SERVER_ERROR"},500);}
}};
export class ChatRoom {
constructor(state,env){this.state=state;this.env=env;this.clients=new Map();}
broadcast(data,exclude){const payload=JSON.stringify(data);for(const socket of this.state.getWebSockets()){if(socket===exclude)continue;try{socket.send(payload);}catch{try{socket.close();}catch{}}}}
presence(){const clients=this.state.getWebSockets();const users=new Map();for(const socket of clients){const tags=this.state.getTags(socket);const id=tags.find(x=>x.startsWith("uid:"))?.slice(4),name=tags.find(x=>x.startsWith("name:"))?.slice(5);if(id)users.set(id,decodeURIComponent(name||"Gebruiker"));}this.broadcast({type:"presence",users:Array.from(users.values())});}
async fetch(request){const url=new URL(request.url);
if(url.pathname==="/connect"&&request.headers.get("upgrade")?.toLowerCase()==="websocket"){
const id=request.headers.get("X-RC-User"),name=request.headers.get("X-RC-Name");if(!id||!name)return new Response("Forbidden",{status:403});
const pair=new WebSocketPair(),client=pair[0],server=pair[1];
this.state.acceptWebSocket(server,["uid:"+id,"name:"+name]);
this.presence();return new Response(null,{status:101,webSocket:client});
}
if(url.pathname==="/broadcast"&&request.method==="POST"){const data=await request.json();if(data?.type==="message")this.broadcast(data);return new Response("ok");}
return new Response("Not found",{status:404});}
webSocketMessage(socket,message){try{const data=JSON.parse(message);if(data.type==="typing"){const tags=this.state.getTags(socket),name=tags.find(x=>x.startsWith("name:"))?.slice(5);this.broadcast({type:"typing",name:decodeURIComponent(name||"Gebruiker"),active:!!data.active},socket);}}catch{}}
webSocketClose(socket){try{socket.close();}catch{}this.presence();}
webSocketError(socket){try{socket.close();}catch{}this.presence();}
}
