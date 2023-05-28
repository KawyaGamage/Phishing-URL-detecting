#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd


# In[2]:


#legitimate files

data1 = pd.read_csv("Benign_list_big_final.csv")
data1.columns = ['URLs']
data1.head()


# In[3]:


#taking 5000 entries only 

legitimateURL = data1.sample(n=5000, random_state = 12).copy()
legitimateURL = legitimateURL.reset_index(drop=True)
legitimateURL.head()


# In[4]:


#phishing files

data2 = pd.read_csv("verified_online.csv")
data2.head()


# In[5]:


#taking 5000 entries only

phishingURL = data2.sample(n = 5000, random_state = 12).copy()
phishingURL = phishingURL.reset_index(drop=True)
phishingURL.head()


# In[6]:


from urllib.parse import urlparse,urlencode
import ipaddress
import re


# In[7]:


#checking domain in URL

def getDomain(url):  
  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
               domain = domain.replace("www.","")
  return domain

#Checking for IP in URL

def IPAddress(url):
  try:
    ipaddress.ip_address(url)
    ipAdd = 1
  except:
    ipAdd = 0
  return ipAdd


# In[8]:


#checking for @ in URL

def AtSign(url):
  if "@" in url:
    at = 1    
  else:
    at = 0    
  return at


# In[9]:


#finding the length of URL

def getLength(url):
  if len(url) < 54:
    length = 0            
  else:
    length = 1            
  return length


# In[10]:


#finding no. of sub pages

def getDepth(url):
  x = urlparse(url).path.split('/')
  depth = 0
  for y in range(len(x)):
    if len(x[y]) != 0:
      depth = depth+1
  return depth


# In[11]:


#findung redirection

def redirect(url):
  redirectnum = url.rfind('//')
  if redirectnum > 6:
    if redirectnum > 7:
      return 1
    else:
      return 0
  else:
    return 0


# In[12]:


#Checking for HTTPS token in URL

def httpDom(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0


# In[13]:


#checking for - mark in URL

def preSuf(url):
    if '-' in urlparse(url).netloc:
        return 1            
    else:
        return 0  


# In[14]:


#checking URL shortening

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"                       r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"                       r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"                       r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"                       r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"                       r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"                       r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"                       r"tr\.im|link\.zip\.net"


# In[15]:


def URLshortening(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0


# In[16]:


get_ipython().system('pip install python-whois')


# In[17]:


import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime


# In[18]:


#checking the web traffic

def web_traffic(url):
  try:
    #Filling the whitespaces in the URL if any
    url = urllib.parse.quote(url)
    rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
    rank = int(rank)
  except TypeError:
        return 1
  if rank <100000:
    return 1
  else:
    return 0


# In[19]:


#finding out the domain age

def DomainAge(domain_name):
  createdate = domain_name.createdate
  expirydate = domain_name.expirydate
  if (isinstance(createdate,str) or isinstance(expirydate,str)):
    try:
      createdate = datetime.strptime(createdate,'%Y-%m-%d')
      expirydate = datetime.strptime(expirydate,"%Y-%m-%d")
    except:
      return 1
  if ((expirydate is None) or (createdate is None)):
      return 1
  elif ((type(expirydate) is list) or (type(createdate) is list)):
      return 1
  else:
    ageofdomain = abs((expirydate - createdate).days)
    if ((ageofdomain/30) < 6):
      age = 1
    else:
      age = 0
  return age


# In[20]:


#finding out the remaining domain time

def domainEnd(domain_name):
  expirydate = domain_name.expirydate
  if isinstance(expirydate,str):
    try:
      expirydate = datetime.strptime(expirydate,"%Y-%m-%d")
    except:
      return 1
  if (expirydate is None):
      return 1
  elif (type(expirydate) is list):
      return 1
  else:
    today = datetime.now()
    end = abs((expirydate - today).days)
    if ((end/30) < 6):
      end = 0
    else:
      end = 1
  return end


# In[21]:


import requests


# In[22]:


#checking for iframe redirection

def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[|]", response.text):
          return 0
      else:
          return 1


# In[23]:


#checking for fake URLs in status bar

def mouseOver(response): 
  if response == "" :
    return 1
  else:
    if re.findall("", response.text):
      return 1
    else:
      return 0


# In[24]:


#finding out how many times it was redirected

def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1


# In[25]:


#checking if right click is disabled

def rightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1


# In[26]:


#extracting features

def featureExtraction(url,label):
    
    features = []
    
    features.append(getDomain(url))
    features.append(IPAddress(url))
    features.append(AtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirect(url))
    features.append(httpDom(url))
    features.append(preSuf(url))
    features.append(URLshortening(url))
    
    
    
    dns = 0
    try:
      domain_name = whois.whois(urlparse(url).netloc)
    except:
      dns = 1

    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))
    
    
    
    try:
      response = requests.get(url)
    except:
      response = ""
    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(forwarding(response))
    features.append(rightClick(response))
    features.append(label)
    
    
    return features


# In[27]:


legitimateURL.shape


# In[28]:


legi_features = []
label = 0

for i in range(0, 5000):
  url = legitimateURL['URLs'][i]
  legi_features.append(featureExtraction(url,label))


# In[29]:


print("Hello World")


# In[30]:


feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                      'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                      'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards', 'Label']

legitimate = pd.DataFrame(legi_features, columns= feature_names)
legitimate.head()


# In[31]:


phishingURL.shape


# In[32]:


phish_features = []
label = 1
for i in range(0, 5000):
  url = phishingURL['url'][i]
  phish_features.append(featureExtraction(url,label))


# In[33]:


feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                      'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                      'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards', 'Label']

phishing = pd.DataFrame(phish_features, columns= feature_names)
phishing.head()


# In[34]:


phishing.to_csv('phishing.csv', index= False)


# In[35]:


legitimate.to_csv('legitimate.csv', index= False)


# In[36]:


urldata = pd.concat([legitimate, phishing]).reset_index(drop=True)
urldata.head()


# In[37]:


urldata.tail()


# In[ ]:




