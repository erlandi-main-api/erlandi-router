package main

import (
 "bytes"
 "crypto/rand"
 "encoding/json"
 "fmt"
 "io"
 "log"
 "net/http"
 "sync"
 "sync/atomic"
 "time"
 fhttp "github.com/bogdanfinn/fhttp"
 tls_client "github.com/bogdanfinn/tls-client"
 "github.com/bogdanfinn/tls-client/profiles"
 tls "github.com/bogdanfinn/utls"
)

const base62="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const maxRequestsPerSession=16
const maxSessionAge=12*time.Minute

type managedSession struct{ID string;Created time.Time;Requests int;Rotations int;LastUsed time.Time}
type sessionManager struct{mu sync.Mutex;pool map[string]*managedSession;rotations uint64;rateLimits uint64;warpRetries uint64;success uint64;failed uint64}
var manager=sessionManager{pool:map[string]*managedSession{}}

func randomPart()string{b:=make([]byte,14);_,_=rand.Read(b);out:=make([]byte,14);for i,v:=range b{out[i]=base62[int(v)%len(base62)]};return string(out)}
func freshIdentity()(string,string){n:=time.Now().UnixMilli();return fmt.Sprintf("ses_%012x%s",^(n*0x1000+1)&0xffffffffffff,randomPart()),fmt.Sprintf("msg_%012x%s",n*0x1000+1,randomPart())}
func (m *sessionManager)identity(key string,force bool)(string,string){m.mu.Lock();defer m.mu.Unlock();now:=time.Now();s:=m.pool[key];if s==nil||force||s.Requests>=maxRequestsPerSession||now.Sub(s.Created)>=maxSessionAge{sid,_:=freshIdentity();rot:=0;if s!=nil{rot=s.Rotations+1;atomic.AddUint64(&m.rotations,1)};s=&managedSession{ID:sid,Created:now,Rotations:rot};m.pool[key]=s};s.Requests++;s.LastUsed=now;_,req:=freshIdentity();return s.ID,req}
func (m *sessionManager)stats()map[string]any{m.mu.Lock();defer m.mu.Unlock();active:=0;requests:=0;for _,s:=range m.pool{active++;requests+=s.Requests};return map[string]any{"active_sessions":active,"session_requests":requests,"rotations":atomic.LoadUint64(&m.rotations),"rate_limits":atomic.LoadUint64(&m.rateLimits),"warp_retries":atomic.LoadUint64(&m.warpRetries),"success":atomic.LoadUint64(&m.success),"failed":atomic.LoadUint64(&m.failed),"rotate_after_requests":maxRequestsPerSession,"rotate_after_minutes":int(maxSessionAge/time.Minute)}}

func bunProfile()profiles.ClientProfile{base:=profiles.Chrome_124;hello:=tls.ClientHelloID{Client:"Bun",Version:"1",SpecFactory:func()(tls.ClientHelloSpec,error){spec,err:=base.GetClientHelloSpec();if err!=nil{return tls.ClientHelloSpec{},err};spec.CipherSuites=[]uint16{tls.TLS_AES_128_GCM_SHA256,tls.TLS_AES_256_GCM_SHA384,tls.TLS_CHACHA20_POLY1305_SHA256,tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,tls.TLS_RSA_WITH_AES_128_GCM_SHA256,tls.TLS_RSA_WITH_AES_256_GCM_SHA384,tls.TLS_RSA_WITH_AES_128_CBC_SHA,tls.TLS_RSA_WITH_AES_256_CBC_SHA};return spec,nil}};return profiles.NewClientProfile(hello,base.GetSettings(),base.GetSettingsOrder(),base.GetPseudoHeaderOrder(),base.GetConnectionFlow(),base.GetPriorities(),base.GetHeaderPriority())}
func makeClient(profile profiles.ClientProfile,proxy string)(tls_client.HttpClient,error){opts:=[]tls_client.HttpClientOption{tls_client.WithTimeoutSeconds(180),tls_client.WithClientProfile(profile)};if proxy!=""{opts=append(opts,tls_client.WithProxyUrl(proxy))};return tls_client.NewHttpClient(tls_client.NewNoopLogger(),opts...)}

func main(){profile:=bunProfile();h:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
 if r.URL.Path=="/stats"{w.Header().Set("content-type","application/json");_ = json.NewEncoder(w).Encode(manager.stats());return}
 target:=r.Header.Get("x-target-url");if target==""{http.Error(w,"missing target",400);return};body,err:=io.ReadAll(r.Body);if err!=nil{http.Error(w,err.Error(),400);return};key:=r.Header.Get("x-opencode-session");if key==""{key="anonymous"}
 do:=func(proxy string,force bool)(*fhttp.Response,error){client,err:=makeClient(profile,proxy);if err!=nil{return nil,err};req,err:=fhttp.NewRequestWithContext(r.Context(),r.Method,target,bytes.NewReader(body));if err!=nil{return nil,err};for k,vs:=range r.Header{if k=="X-Target-Url"||k=="Host"||k=="Content-Length"{continue};for _,v:=range vs{req.Header.Add(k,v)}};sid,rid:=manager.identity(key,force);req.Header.Set("x-opencode-session",sid);req.Header.Set("x-opencode-session-id",sid);req.Header.Set("x-session-affinity",sid);req.Header.Set("x-session-id",sid);req.Header.Set("x-opencode-request",rid);req.Header.Set("x-opencode-project","global");return client.Do(req)}
 resp,err:=do("",false);if err!=nil{resp,err=do("",false)}
 if err==nil&&resp.StatusCode==429{atomic.AddUint64(&manager.rateLimits,1);resp.Body.Close();resp,err=do("",true)}
 if err==nil&&resp.StatusCode==429{atomic.AddUint64(&manager.rateLimits,1);atomic.AddUint64(&manager.warpRetries,1);resp.Body.Close();resp,err=do("http://127.0.0.1:63013",true)}
 if err!=nil{atomic.AddUint64(&manager.failed,1);http.Error(w,err.Error(),502);return};if resp.StatusCode<400{atomic.AddUint64(&manager.success,1)}else{atomic.AddUint64(&manager.failed,1)};defer resp.Body.Close();for k,vs:=range resp.Header{for _,v:=range vs{w.Header().Add(k,v)}};w.WriteHeader(resp.StatusCode);_,_=io.Copy(w,resp.Body)
 });log.Fatal((&http.Server{Addr:"127.0.0.1:63015",Handler:h,ReadHeaderTimeout:15*time.Second}).ListenAndServe())}
