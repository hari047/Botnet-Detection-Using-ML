#!/usr/bin/env python
# coding: utf-8

# In[1]:


import graphlab as gl
import tensorflow as tf
import matplotlib.pyplot as plt


# In[2]:


SF = gl.SFrame.read_csv('botnetog.csv',verbose=False)
print("Done reading")
SF.head


# In[3]:


SF['tcp_Flags'] = SF['tcp_Flags'].apply(lambda x:int(x,16) if x!='' else 0)


# In[4]:


Protocols = sorted(SF['Protocol'].unique())
#print Protocols


# ## Some analysis for number of packets of each protocol type

# IRC
#     "192.168.2.112",
#     "131.202.243.84",
#     "192.168.5.122",
#     "198.164.30.2",
#     "192.168.2.110",
#     "192.168.5.122",
#     "192.168.4.118",
#     "192.168.5.122",
#     "192.168.2.113",
#     "192.168.5.122",
#     "192.168.1.103",
#     "192.168.5.122",
#     "192.168.4.120",
#     "192.168.5.122",
#     "192.168.2.112",
#     "192.168.2.110",
#     "192.168.2.112",
#     "192.168.4.120",
#     "192.168.2.112",
#     "192.168.1.103",
#     "192.168.2.112",
#     "192.168.2.113",
#     "192.168.2.112",
#     "192.168.4.118",
#     "192.168.2.112",
#     "192.168.2.109",
#     "192.168.2.112",
#     "192.168.2.105",
#     "192.168.1.105",
#     "192.168.5.122",

# In[5]:


iplist = [
    "147.32.84.180",
    "147.32.84.170",
    "147.32.84.150",
    "147.32.84.140",
    "147.32.84.130",
    "147.32.84.160",
    "10.0.2.15",
    "192.168.106.141",
    "192.168.106.131",
    "172.16.253.130",
    "172.16.253.131",
    "172.16.253.129",
    "172.16.253.240",
    "74.78.117.238",
    "158.65.110.24",
    "192.168.3.35",
    "192.168.3.25",
    "192.168.3.65",
    "172.29.0.116",
    "172.29.0.109",
    "172.16.253.132",
    "192.168.248.165",
    "10.37.130.4",
    "131.202.243.84", 
    "198.164.30.2", "192.168.5.122", 
    "192.168.5.122", 
    "192.168.5.122", "192.168.5.122", "192.168.5.122", 
    "192.168.2.110", 
    "192.168.4.120", "192.168.1.103",
    "192.168.2.113", "192.168.4.118" , "192.168.2.109", "192.168.2.105", "192.168.5.122"]

MasterBot = [ ("192.168.2.112", "131.202.243.84"), ("192.168.5.122", "198.164.30.2"), ("192.168.2.110", "192.168.5.122"),( "192.168.4.118", "192.168.5.122"), ("192.168.2.113", "192.168.5.122"), ("192.168.1.103", "192.168.5.122"), ("192.168.4.120", "192.168.5.122"), ("192.168.2.112", "192.168.2.110"), ("192.168.2.112", "192.168.4.120"), ("192.168.2.112", "192.168.1.103"), ("192.168.2.112", "192.168.2.113"), ("192.168.2.112", "192.168.4.118"), ("192.168.2.112", "192.168.2.109"), ("192.168.2.112", "192.168.2.105"), ("192.168.1.105", "192.168.5.122")]

iplist = gl.SArray(iplist)
iplist = iplist.unique() 
iplist = list(iplist)

def fcheckIP(x):
    if (x['Source'] in iplist) or (x['Destination'] in iplist):
        return 1
    else:
        if ((x['Source'],x['Destination'])  in MasterBot ) or ((x['Destination'],x['Source'])  in MasterBot ) :
            return 1
        else:
            return 0
        

SF['isBot'] = SF[['Source','Destination']].apply(lambda x: fcheckIP(x))


# Botnet Labelled packets and their percentage.
# 

# In[6]:


temp = len(SF[SF['isBot']==1])
print temp, (temp*1.0)/len(SF)*100


# # Sorting will help in identifying flow effectively

# ## Flow Identification Bidirectional

# ## No More Brainstorming, this is TRUE !!!!!!!!

# In[7]:


def flow_id(x):
    if x['Source']>x['Destination']:
        return x['Source']+'-'+x['Destination']+'-'+str(x['Source Port'])+'-'+str(x['Destination Port'])+'-'+x['Protocol']
    else:
        return x['Destination']+'-'+x['Source']+'-'+str(x['Destination Port'])+'-'+str(x['Source Port'])+'-'+x['Protocol']
SF['UFid'] = SF.apply(lambda x:flow_id(x))

#For identifying IOPR
SF['Forward'] = SF.apply(lambda x: 1 if x['Source']>x['Destination'] else 0 )

## function for comparing two different flows based on columns
def compareUF(x,y):
    if x!=y:
        return False
    return True



##Code for logic of Bidirectional flow identification
import pickle 

FlowNo = 0 ##Unique Flow Number for each flow
prev = None
Flow = []     ##Stores all flows in form of list of dictionary 
#cFlow = []    ##Store the current flow (all details)
count = 0
fc = 0
startTime = None   ##Start Time of each flow to implement timeout
SF = SF.sort(['UFid','Time'])
print 'Done Sorting'
for x in SF:
    if count%500000 == 0:
        print 'Running '+str(count)+' Done !'
        
    count = count+1
    
    if prev is None:
        if startTime is None:
            startTime = x['Time']
        Flow.append(FlowNo)
        
        prev = x['UFid']
    elif compareUF(x['UFid'],prev):
        if x['tcp_Flags']&1:
            Flow.append(FlowNo)
            prev = None
            startTime = None
            FlowNo = FlowNo + 1

        elif x['Time']-startTime>=3600:
            FlowNo = FlowNo + 1
            Flow.append(FlowNo)
            prev = None
            startTime = x['Time']
            
        else:
            
            Flow.append(FlowNo)
            prev = x['UFid']

    else:
        FlowNo = FlowNo + 1
        Flow.append(FlowNo)
        prev = x['UFid']
        startTime = x['Time']


print len(gl.SArray(Flow).unique())



SF['Flow'] = gl.SArray(Flow)
temp = SF.groupby('Flow',{
            'Count':gl.aggregate.COUNT()
        })
print len(temp[temp['Count']>1])


# In[9]:


def flow_id(x):
    if x['Source']>x['Destination']:
        return x['Source']+'-'+x['Destination']+'-'+str(x['Source Port'])+'-'+str(x['Destination Port'])+'-'+x['Protocol']
    else:
        return x['Destination']+'-'+x['Source']+'-'+str(x['Destination Port'])+'-'+str(x['Source Port'])+'-'+x['Protocol']
SF['UFid'] = SF.apply(lambda x:flow_id(x))


# In[11]:


## function for comparing two different flows based on columns
def compareUF(x,y):
    if x!=y:
        return False
    return True

# In[13]:


SF['Flow'] = gl.SArray(Flow)
temp = SF.groupby('Flow',{
            'Count':gl.aggregate.COUNT()
        })
len(temp[temp['Count']>1])


# In[15]:


temp = SF.groupby('Flow',{
        'NumBots' : gl.aggregate.SUM('isBot')
    })
NumBotFlows = len(temp[temp['NumBots']>1])
print NumBotFlows, NumBotFlows*1.0/len(SF['Flow'].unique()) 


# In[16]:


len(Flow)


# In[17]:


len(SF)


# In[18]:


SF['FlowNo.'] = gl.SArray(Flow)


# In[19]:


##Code for checking authenticity of flow logic
#STD[(STD['Source']=='0.0.0.0')&(STD['Destination']=='255.255.255.255')&(STD['Source Port']=='68')&(STD['Destination Port']=='67')].sort('Time')


# In[20]:


## Code to check if in any flows there are some No.s which are in decreasing order (Indicative or Decrepancies)
## UPDATE: No. does not indicate same relation in time, so Data collected is right !
"""count = 0
for li in Flow:
    for i in range(1,len(li)):
        if li[i]<li[i-1]:
            #print li
            count = count+1
            break;
print count"""


# In[21]:


import pickle
pickle.dump(Flow,open('Flow.pkl','w'))


# In[22]:


SF.save('ISCX_Botnet-Testing_Ports_Only_Sorted_Flow_BD.csv')


# In[23]:


def tfn(x):
    if 'udp' in x.split(':'):
        return 1
    return 0
SF['hasUDP'] = SF['Protocols in frame'].apply(lambda x:tfn(x))


# In[24]:


SF.head


# In[25]:


## Ratio of incoming to outgoing packets
temp = SF.groupby('FlowNo.',{
        'NumForward' : gl.aggregate.SUM('Forward'),
        'Total' : gl.aggregate.COUNT()
    })
temp['IOPR']= temp.apply(lambda x: ((x['Total']-x['NumForward'])*1.0)/x['NumForward'] if x['NumForward'] !=0 else (-1) )
temp = temp['FlowNo.','IOPR']


# In[26]:


len(temp[temp['IOPR']!=-1])


# In[27]:


SF = SF.join(temp,on='FlowNo.')
SF.head


# In[28]:


SF['IOPR']


# In[29]:


## First Packet Length
FlowFeatures = ['Source','Destination','Source Port','Destination Port','Protocol']
FPL = SF.groupby(['FlowNo.'],{
        'Time':gl.aggregate.MIN('Time')
    })
print len(FPL)
FPL = FPL.join(SF,on =['FlowNo.','Time'])[['FlowNo.','Length']].unique()
FPL = FPL.groupby(['FlowNo.'],{
        'FPL':gl.aggregate.AVG('Length')
    })
print len(FPL)


# In[33]:

SF = SF.join(FPL, on ='FlowNo.')
del(FPL)





# In[50]:

features = ['Answer RRs',
 'BytesEx',
 'Destination',
 'Destination Port',
 'Duration',
 'FPL',
 'IP_Flags',
 'Info',
 'Length',
 'Next sequence number',
 'No.',
 'NumPackets',
 'Protocol',
 'Protocols in frame',
 'SameLenPktRatio',
 'Sequence number',
 'Source',
 'Source Port',
 'StdDevLen',
 'TCP Segment Len',
 'Time',
 'isBot',
 'tcp_Flags',
 'FlowNo.',
 'udp_Length',
 'IOPR']
SF = SF[features]


# In[52]:

## Average packets per second
temp =  SF.groupby(['FlowNo.'],{
        'NumPackets':gl.aggregate.COUNT()
    })
temp = temp.join(timeF,on=['FlowNo.'])
temp['AvgPktPerSec'] = temp.apply(lambda x:0.0 if x['Duration'] == 0.0 else x['NumPackets']*1.0/x['Duration'])
temp = temp[['FlowNo.','AvgPktPerSec']]
SF = SF.join(temp, on ='FlowNo.')


# In[73]:

## Null Packets handling
def checkNull(x):
    if(x['TCP Segment Len']=='0' or x['udp_Length']==8 ):
        return 1
    elif('ipx' in x['Protocols in frame'].split(':')):
        l = x['Length'] - 30
        if('eth' in x['Protocols in frame'].split(':')):
            l = l - 14
        if('ethtype' in x['Protocols in frame'].split(':')):
            l = l - 2
        if('llc' in x['Protocols in frame'].split(':')):
            l = l - 8
        if(l==0 or l==-1):
            return 1
    return 0

##This is just a sample of the source code. For more, contact me directly @ harirangaraj97@gmail.com 