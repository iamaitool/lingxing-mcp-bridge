import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createBridge, Lingxing} from './server.mjs';
const config = {publicUrl:'https://bridge.example',key:'test-only-upstream-key',password:'test-only-password-long',signingKey:'test-only-signing-key-over-thirty-two-characters'};
const verifier = 'v'.repeat(64);
const challenge = createHash('sha256').update(verifier).digest('base64url');
const callback = 'https://chatgpt.com/connector_platform_oauth_redirect';
async function fixture(t, overrides={}) {
  const calls=[];
  const upstream={request:async (method,params)=>{calls.push({method,params});return {result:method==='tools/list'?{tools:[{name:'erp_listing',inputSchema:{type:'object'}},{name:'put_campaigns_sp'}],nextCursor:'page2'}:{content:[{type:'text',text:'mock report'}]}};}};
  const server=createBridge({...config,...overrides},upstream);
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  t.after(()=>new Promise(r=>server.close(r)));
  const base=`http://127.0.0.1:${server.address().port}`;
  const request=(path,options)=>fetch(base+path,{redirect:'manual',...options});
  const post=(path,data,headers={})=>request(path,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(data)});
  return {request,post,calls};
}
async function authorize(f,password=config.password) {
  const registration=await f.post('/register',{redirect_uris:[callback],token_endpoint_auth_method:'none'});
  assert.equal(registration.status,201);
  const {client_id}=await registration.json();
  const page=await f.request('/authorize?'+new URLSearchParams({client_id,redirect_uri:callback,response_type:'code',code_challenge:challenge,code_challenge_method:'S256',resource:config.publicUrl+'/mcp',scope:'lingxing.read',state:'original-state'}));
  assert.equal(page.status,200);
  const cookie=page.headers.get('set-cookie').split(';')[0];
  const request_id=(await page.text()).match(/name="request_id" value="([^"]+)"/)[1];
  const login=await f.post('/authorize',{request_id,password},{Cookie:cookie,Origin:config.publicUrl});
  return {login,client_id};
}
async function token(f) {
  const {login,client_id}=await authorize(f);
  assert.equal(login.status,303);
  const redirect=new URL(login.headers.get('location'));
  assert.equal(redirect.searchParams.get('state'),'original-state');
  assert.equal(redirect.searchParams.get('iss'),config.publicUrl);
  const grant={grant_type:'authorization_code',client_id,redirect_uri:callback,code:redirect.searchParams.get('code'),code_verifier:verifier,resource:config.publicUrl+'/mcp'};
  const response=await f.post('/token',grant);
  assert.equal(response.status,200);
  const result=await response.json();
  return {...result,grant};
}

test('unconfigured deployment stays closed but has a public health check',async t=>{
  const f=await fixture(t,{key:''});
  assert.equal((await f.request('/healthz')).status,200);
  assert.equal((await f.post('/mcp',{})).status,503);
  assert.equal((await f.request('/.well-known/oauth-protected-resource/mcp')).status,503);
});
test('discovery advertises S256 and issuer identification; unauthenticated calls blocked',async t=>{
  const f=await fixture(t);
  const meta=await (await f.request('/.well-known/oauth-authorization-server')).json();
  assert.deepEqual(meta.code_challenge_methods_supported,['S256']);
  assert.equal(meta.authorization_response_iss_parameter_supported,true);
  const unauth=await f.post('/mcp',{jsonrpc:'2.0',id:1,method:'tools/list'});
  assert.equal(unauth.status,401);
  assert.match(unauth.headers.get('www-authenticate'),/oauth-protected-resource/);
  assert.equal(f.calls.length,0);
});
test('registration rejects external callbacks, query injection and unsupported client auth',async t=>{
  const f=await fixture(t);
  for(const uri of ['https://attacker.example/callback',callback+'?next=attacker','https://chatgpt.com.attacker.example/connector_platform_oauth_redirect']) assert.equal((await f.post('/register',{redirect_uris:[uri]})).status,400);
  assert.equal((await f.post('/register',{redirect_uris:[callback],token_endpoint_auth_method:'client_secret_post'})).status,400);
});
test('password and browser CSRF are required',async t=>{
  const f=await fixture(t);
  assert.equal((await authorize(f,'wrong-password')).login.status,403);
  assert.equal((await f.post('/authorize',{request_id:'fake',password:config.password},{Origin:config.publicUrl})).status,400);
  assert.equal(f.calls.length,0);
});
test('OAuth PKCE flow, state/issuer, one-time code and read-only enforcement',async t=>{
  const f=await fixture(t); const {access_token,grant}=await token(f);
  assert.equal((await f.post('/token',grant)).status,400);
  const headers={Authorization:'Bearer '+access_token};
  const init=await (await f.post('/mcp',{jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-06-18'}},headers)).json();
  assert.equal(init.result.protocolVersion,'2025-06-18');
  const list=await (await f.post('/mcp',{jsonrpc:'2.0',id:2,method:'tools/list'},headers)).json();
  assert.deepEqual(list.result.tools.map(t=>t.name),['erp_listing']);
  assert.equal(list.result.nextCursor,'page2');
  const call=await (await f.post('/mcp',{jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'erp_listing',arguments:{}}},headers)).json();
  assert.equal(call.result.content[0].text,'mock report');
  const denied=await (await f.post('/mcp',{jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'put_campaigns_sp'}},headers)).json();
  assert.equal(denied.error.code,-32602);
  assert.equal(f.calls.length,2);
  assert.equal((await f.post('/mcp',{jsonrpc:'2.0',id:5,method:'ping'},{Authorization:'Bearer '+access_token+'tampered'})).status,401);
  assert.equal((await f.post('/mcp',{jsonrpc:'2.0',id:6,method:'ping'},{...headers,Origin:'https://attacker.example'})).status,403);
});
test('wrong PKCE verifier cannot redeem an authorization code',async t=>{
  const f=await fixture(t); const {login,client_id}=await authorize(f);
  const code=new URL(login.headers.get('location')).searchParams.get('code');
  const r=await f.post('/token',{grant_type:'authorization_code',client_id,redirect_uri:callback,code,code_verifier:'x'.repeat(64)});
  assert.equal(r.status,400);
});
test('tokens are audience bound and expire',async t=>{
  const f=await fixture(t); const {access_token}=await token(f);
  const other=await fixture(t,{publicUrl:'https://other.example'});
  assert.equal((await other.post('/mcp',{jsonrpc:'2.0',id:1,method:'ping'},{Authorization:'Bearer '+access_token})).status,401);
  const realNow=Date.now;
  try {
    Date.now=()=>realNow()+43201*1000;
    assert.equal((await f.post('/mcp',{jsonrpc:'2.0',id:1,method:'ping'},{Authorization:'Bearer '+access_token})).status,401);
  } finally {Date.now=realNow;}
});
test('upstream uses server key/session, parses SSE and initializes once',async()=>{
  const requests=[];
  const fake=async (url,options)=>{
    const payload=JSON.parse(options.body);requests.push({...payload,headers:options.headers,url});
    if(payload.method==='initialize') return new Response(JSON.stringify({jsonrpc:'2.0',id:payload.id,result:{protocolVersion:'2025-03-26'}}),{headers:{'Content-Type':'application/json','Mcp-Session-Id':'private-session'}});
    if(payload.method==='notifications/initialized') return new Response(null,{status:202});
    return new Response(`event: message\r\ndata: ${JSON.stringify({jsonrpc:'2.0',id:payload.id,result:{tools:[]}})}\r\n\r\n`,{headers:{'Content-Type':'text/event-stream'}});
  };
  const up=new Lingxing('test-server-side-key',fake);
  await Promise.all([up.request('tools/list',{}),up.request('tools/list',{})]);
  assert.equal(requests.filter(r=>r.method==='initialize').length,1);
  assert.equal(requests.at(-1).headers['Mcp-Session-Id'],'private-session');
  assert.ok(requests.every(r=>r.headers['X-Mcp-Key']==='test-server-side-key' && !r.headers.Authorization));
});
