from pathlib import Path
import importlib.util
import json
import os
import sys
import urllib.request
root=Path(__file__).parent
sys.path.insert(0,'C:/Users/{{WIN_USER}}/Projects/Cyber Lab/spiderfoot-4.0')
os.environ['SPIDERFOOT_CACHE']=str(root/'account-test-cache')
spec=importlib.util.spec_from_file_location('patched_accounts',Path('C:/Users/{{WIN_USER}}/Projects/Cyber Lab/spiderfoot-4.0/modules/sfp_accounts.py'))
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
url='https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json'
with urllib.request.urlopen(url,timeout=20) as response:
    raw=response.read(2*1024*1024)
data=json.loads(raw)
assert isinstance(data['sites'],list)
class Source:
    content='valid account test-user'
    code='200'
    def dictnames(self): return []
    def dictwords(self): return []
    def cacheGet(self,*a): return None
    def cachePut(self,*a): pass
    def fetchUrl(self,url,**kw):
        self.last=(url,kw)
        return {'content':raw.decode(),'code':'200'} if url.endswith('wmn-data.json') else {'content':self.content,'code':self.code}
s=Source()
m=mod.sfp_accounts()
m.setup(s,{'_fetchtimeout':5,'_useragent':'SpiderFoot'})
assert not m.errorState and len(m.sites)>300
print('PASS current official directory loads:',len(m.sites),'enabled records')
row={'name':'Test','cat':'test','uri_check':'https://example.test/{account}', 'e_code':200,'e_string':'valid account','m_string':'missing account','headers':{'Accept':'application/json'},'post_body':'{"name":"{account}"}'}
m.checkSite('test-user',row)
assert list(m.siteResults.values())==[True]
assert s.last[1]['postData']=='{"name":"test-user"}' and s.last[1]['headers']==row['headers']
m.siteResults={}; s.content='valid account test-user missing account'
m.checkSite('test-user',row)
assert list(m.siteResults.values())==[False]
m.siteResults={};s.content='valid account test-user';s.code='404'
m.checkSite('test-user',row)
assert list(m.siteResults.values())==[False]
print('PASS existence/missing markers, HTTP codes, and request fields')
