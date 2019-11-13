#!/usr/bin/env python
# coding: utf-8

# In[1]:


import graphlab as gl
import tensorflow as tf
import matplotlib.pyplot as plt


# In[2]:


SF = gl.SFrame.read_csv('botnetog.csv',verbose=False)
print "Done reading"
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


# In[8]:



##Code for logic of Bidirectional flow identification
import pickle 

FlowNo = 0 ##Unique Flow Number for each flow
prev = None
Flow = []     ##Stores all flows in form of list of dictionary 
#cFlow = []    ##Store the current flow (all details)
count = 0
fc = 0
startTime = None   ##Start Time of each flow to implement timeout
#SF = SF.sort(['UFid','Time'])
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
        if x['tcp_Flags']&1 or x['tcp_Flags']&4:
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


# In[10]:


#For identifying IOPR
SF['Forward'] = SF.apply(lambda x: 1 if x['Source']>x['Destination'] else 0 )


# In[11]:


## function for comparing two different flows based on columns
def compareUF(x,y):
    if x!=y:
        return False
    return True


# In[12]:


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


# ## 18/10/2016

# In[35]:

## Number of packets per flow
temp = SF.groupby(['FlowNo.'],{
        'NumPackets':gl.aggregate.COUNT()
    })
print temp.head(3)
SF = SF.join(temp, on ='FlowNo.')
del(temp)


# In[ ]:

## Number of bytes exchanged
temp = SF.groupby(['FlowNo.'],{
        'BytesEx':gl.aggregate.SUM('Length')
    })
SF = SF.join(temp, on ='FlowNo.')
del(temp)


# In[38]:

## Standard deviation of packet length
temp = SF.groupby(['FlowNo.'],{
        'StdDevLen':gl.aggregate.STDV('Length')
    })
SF = SF.join(temp, on ='FlowNo.')
del(temp)


# In[40]:

## Same length packet ratio
temp2 = SF.groupby(['FlowNo.'],{
        'SameLenPktRatio':gl.aggregate.COUNT_DISTINCT('Length')
    })
##temp from number of packets computation
temp = SF.groupby(['FlowNo.'],{
        'NumPackets':gl.aggregate.COUNT()
    })
temp = temp.join(temp2,on='FlowNo.')
temp['SameLenPktRatio'] = temp['SameLenPktRatio']*1.0/temp['NumPackets']
temp2 = None
temp = temp[['FlowNo.','SameLenPktRatio']]
SF = SF.join(temp, on ='FlowNo.')


# In[41]:

## Duration of flow
timeF = SF.groupby(['FlowNo.'],{
        'startTime':gl.aggregate.MIN('Time'),
        'endTime':gl.aggregate.MAX('Time')
    })
timeF['Duration'] = timeF['endTime'] - timeF['startTime']
timeF = timeF[['FlowNo.','Duration']]
SF = SF.join(timeF, on ='FlowNo.')


# In[45]:

sorted(SF.column_names())


# In[30]:




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


# In[53]:

##Average Bits Per Second
temp = SF.groupby(['FlowNo.'],{
        'BytesEx':gl.aggregate.SUM('Length')
    })
temp = temp.join(timeF,on=['FlowNo.'])
temp['BitsPerSec'] = temp.apply(lambda x:0.0 if x['Duration'] == 0.0 else x['BytesEx']*8.0/x['Duration'])
temp = temp[['FlowNo.','BitsPerSec']]
SF = SF.join(temp, on ='FlowNo.')


# In[55]:

## Average Packet Lentgth
temp = SF.groupby(['FlowNo.'],{
        'APL':gl.aggregate.AVG('Length')
    })
SF = SF.join(temp, on ='FlowNo.')


# In[ ]:

## Number of Reconnects, sort FlowNo, SeqNo


# In[56]:

def tfn(x):
    if 'udp' in x.split(':') or 'tcp' in x.split(':'):
        return 1
    return 0
temp = list(SF['Protocols in frame'].apply(lambda x:tfn(x)))


# In[57]:

len(temp)


# In[58]:

sum(temp)


# In[60]:



# In[62]:

print len(SF[SF['Protocols in frame']=='eth:ethertype:ip:icmp:ip:tcp:http:urlencoded-form']),len(SF[SF['Protocols in frame']=='eth:ethertype:ip:icmp:ip:tcp']),len(SF[SF['Protocols in frame']=='eth:ethertype:ip:icmp:ip:tcp:http:data'])


# In[64]:

## Inter arrival time
SF['IAT'] = 0
SF = SF.sort(['FlowNo.','Time'])
prev = None
prevT = None
li = []
for x in SF:
    if prev is None or x['FlowNo.']!= prev:
        li.append(0)
    else:
        li.append(x['Time']-prevT)        
    prev = x['FlowNo.']
    prevT = x['Time']
SF['IAT'] = gl.SArray(li)


# In[65]:

len(SF)


# In[66]:

print len(SF[SF['Protocols in frame']=='eth:ipx'])


# In[67]:

SF.save('Bidirectional_Train_Bot_features_till_IAT.csv')


# # Is Null feature

# ### Number of TCP Null packets

# In[68]:


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


# In[74]:

SF['isNull'] = SF.apply(lambda x:checkNull(x))


# In[75]:



# In[76]:

NPEx = SF.groupby(['FlowNo.'],{
        'NPEx':gl.aggregate.SUM('isNull')
    })
SF = SF.join(NPEx, on ='FlowNo.')


# ### Number of Reconnects - considering only TCP reconnects, using sequence number

# In[ ]:



# In[79]:

recon = SF[SF['Sequence number']!=''].groupby(['FlowNo.'],{
        'total_seq_no.' : gl.aggregate.COUNT('Sequence number'),
        'distinct_seq_no.' : gl.aggregate.COUNT_DISTINCT('Sequence number')
    })
recon['reconnects'] = recon['total_seq_no.'] - recon['distinct_seq_no.']
recon.head()
recon = recon[['FlowNo.','reconnects']]
SF = SF.join(recon,on='FlowNo.',how='left')
len(SF)


# In[81]:

#To identify records where reconnect check was not applied like UDP etc
SF.fillna('reconnects',-1)


# In[ ]:

#SF[SF['FlowNo.']==79732]['Info']


# A lot of these reconnects can be simple retransmissions - due to out of order/timeout etcb

# ### 22-10-2016

# In[83]:



# In[15]:

print min(SF['Time']),max(SF['Time'])


# # 28/10/16

# Bidirectional Flowscombining all features and labels

# In[84]:


# In[85]:

SF.save('Bidirectional_Train_Botnet_all_features.csv')


# In[ ]:

#sf_valid_train, sf_test = SF.random_split(.8, seed=5)
#sf_valid, sf_train = sf_valid_train.random_split(.2, seed=5)
#X_train, y_train = sf_train.drop('isBot'), sf_train['isBot']
#X_valid, y_valid = sf_valid_train
#X_train_valid, y_train_valid = X[:3475000], y[:3475000]
#X_test, y_test = X[3475000:], y[3475000:]



# In[89]:

features = SF.column_names()


# In[32]:


SF2 = gl.SFrame.read_csv('botnettest.csv',verbose=False)
print "Done reading"
SF2.head
SF2 = SF2[(SF2['Source Port']!='')&(SF2['Destination Port']!='')]
SF2['tcp_Flags'] = SF2['tcp_Flags'].apply(lambda x:int(x,16) if x!='' else 0)
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
        

SF2['isBot'] = SF2[['Source','Destination']].apply(lambda x: fcheckIP(x))

def flow_id(x):
    if x['Source']>x['Destination']:
        return x['Source']+'-'+x['Destination']+'-'+str(x['Source Port'])+'-'+str(x['Destination Port'])+'-'+x['Protocol']
    else:
        return x['Destination']+'-'+x['Source']+'-'+str(x['Destination Port'])+'-'+str(x['Source Port'])+'-'+x['Protocol']
SF2['UFid'] = SF2.apply(lambda x:flow_id(x))


#For identifying IOPR
SF2['Forward'] = SF2.apply(lambda x: 1 if x['Source']>x['Destination'] else 0 )


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
SF2 = SF2.sort(['UFid','Time'])
print 'Done Sorting'
for x in SF2:
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


SF2['Flow'] = gl.SArray(Flow)
temp = SF2.groupby('Flow',{
            'Count':gl.aggregate.COUNT()
        })
len(temp[temp['Count']>1])


temp = SF2.groupby('Flow',{
        'NumBots' : gl.aggregate.SUM('isBot')
    })
NumBotFlows = len(temp[temp['NumBots']>1])
print NumBotFlows, NumBotFlows*1.0/len(SF2['Flow'].unique()) 

SF2['FlowNo.'] = gl.SArray(Flow)

import pickle
pickle.dump(Flow,open('Flow.pkl','w'))

SF2.save('ISCX_Botnet-Testing_Ports_Only_Sorted_Flow_BD.csv')


def tfn(x):
    if 'udp' in x.split(':'):
        return 1
    return 0
SF2['hasUDP'] = SF2['Protocols in frame'].apply(lambda x:tfn(x))


## Ratio of incoming to outgoing packets
temp = SF2.groupby('FlowNo.',{
        'NumForward' : gl.aggregate.SUM('Forward'),
        'Total' : gl.aggregate.COUNT()
    })
temp['IOPR']= temp.apply(lambda x: ((x['Total']-x['NumForward'])*1.0)/x['NumForward'] if x['NumForward'] !=0 else (-1) )
temp = temp['FlowNo.','IOPR']


SF2 = SF2.join(temp,on='FlowNo.')
SF2.head

## First Packet Length
FlowFeatures = ['Source','Destination','Source Port','Destination Port','Protocol']
FPL = SF2.groupby(['FlowNo.'],{
        'Time':gl.aggregate.MIN('Time')
    })
print len(FPL)
FPL = FPL.join(SF2,on =['FlowNo.','Time'])[['FlowNo.','Length']].unique()
FPL = FPL.groupby(['FlowNo.'],{
        'FPL':gl.aggregate.AVG('Length')
    })
print len(FPL)


# In[33]:

SF2 = SF2.join(FPL, on ='FlowNo.')
del(FPL)


# ## 18/10/2016

# In[35]:

## Number of packets per flow
temp = SF2.groupby(['FlowNo.'],{
        'NumPackets':gl.aggregate.COUNT()
    })
print temp.head(3)
SF2 = SF2.join(temp, on ='FlowNo.')
del(temp)


# In[ ]:

## Number of bytes exchanged
temp = SF2.groupby(['FlowNo.'],{
        'BytesEx':gl.aggregate.SUM('Length')
    })
SF2 = SF2.join(temp, on ='FlowNo.')
del(temp)


# In[38]:

## Standard deviation of packet length
temp = SF2.groupby(['FlowNo.'],{
        'StdDevLen':gl.aggregate.STDV('Length')
    })
SF2 = SF2.join(temp, on ='FlowNo.')
del(temp)


# In[40]:

## Same length packet ratio
temp2 = SF2.groupby(['FlowNo.'],{
        'SameLenPktRatio':gl.aggregate.COUNT_DISTINCT('Length')
    })
##temp from number of packets computation
temp = SF2.groupby(['FlowNo.'],{
        'NumPackets':gl.aggregate.COUNT()
    })
temp = temp.join(temp2,on='FlowNo.')
temp['SameLenPktRatio'] = temp['SameLenPktRatio']*1.0/temp['NumPackets']
temp2 = None
temp = temp[['FlowNo.','SameLenPktRatio']]
SF2 = SF2.join(temp, on ='FlowNo.')


# In[41]:

## Duration of flow
timeF = SF2.groupby(['FlowNo.'],{
        'startTime':gl.aggregate.MIN('Time'),
        'endTime':gl.aggregate.MAX('Time')
    })
timeF['Duration'] = timeF['endTime'] - timeF['startTime']
timeF = timeF[['FlowNo.','Duration']]
SF2 = SF2.join(timeF, on ='FlowNo.')


# In[45]:

sorted(SF2.column_names())





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
SF2 = SF2[features]


# In[52]:

## Average packets per second
temp =  SF2.groupby(['FlowNo.'],{
        'NumPackets':gl.aggregate.COUNT()
    })
temp = temp.join(timeF,on=['FlowNo.'])
temp['AvgPktPerSec'] = temp.apply(lambda x:0.0 if x['Duration'] == 0.0 else x['NumPackets']*1.0/x['Duration'])
temp = temp[['FlowNo.','AvgPktPerSec']]
SF2 = SF2.join(temp, on ='FlowNo.')


# In[53]:

##Average Bits Per Second
temp = SF2.groupby(['FlowNo.'],{
        'BytesEx':gl.aggregate.SUM('Length')
    })
temp = temp.join(timeF,on=['FlowNo.'])
temp['BitsPerSec'] = temp.apply(lambda x:0.0 if x['Duration'] == 0.0 else x['BytesEx']*8.0/x['Duration'])
temp = temp[['FlowNo.','BitsPerSec']]
SF2 = SF2.join(temp, on ='FlowNo.')


# In[55]:

## Average Packet Lentgth
temp = SF2.groupby(['FlowNo.'],{
        'APL':gl.aggregate.AVG('Length')
    })
SF2 = SF2.join(temp, on ='FlowNo.')


# In[ ]:

## Number of Reconnects, sort FlowNo, SeqNo


# In[56]:

def tfn(x):
    if 'udp' in x.split(':') or 'tcp' in x.split(':'):
        return 1
    return 0
temp = list(SF2['Protocols in frame'].apply(lambda x:tfn(x)))


# In[57]:

len(temp)


# In[58]:

sum(temp)


# In[60]:



# In[62]:

print len(SF2[SF2['Protocols in frame']=='eth:ethertype:ip:icmp:ip:tcp:http:urlencoded-form']),len(SF2[SF2['Protocols in frame']=='eth:ethertype:ip:icmp:ip:tcp']),len(SF2[SF2['Protocols in frame']=='eth:ethertype:ip:icmp:ip:tcp:http:data'])


# In[64]:

## Inter arrival time
SF2['IAT'] = 0
SF2 = SF2.sort(['FlowNo.','Time'])
prev = None
prevT = None
li = []
for x in SF2:
    if prev is None or x['FlowNo.']!= prev:
        li.append(0)
    else:
        li.append(x['Time']-prevT)        
    prev = x['FlowNo.']
    prevT = x['Time']
SF2['IAT'] = gl.SArray(li)


# In[65]:

len(SF2)


# In[66]:

print len(SF2[SF2['Protocols in frame']=='eth:ipx'])


# In[67]:

SF2.save('Bidirectional_Test_Bot_features_till_IAT.csv')


# # Is Null feature

# ### Number of TCP Null packets

# In[68]:


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


# In[74]:

SF2['isNull'] = SF2.apply(lambda x:checkNull(x))


# In[75]:



# In[76]:

NPEx = SF2.groupby(['FlowNo.'],{
        'NPEx':gl.aggregate.SUM('isNull')
    })
SF2 = SF2.join(NPEx, on ='FlowNo.')


# ### Number of Reconnects - considering only TCP reconnects, using sequence number

# In[ ]:



# In[79]:

recon = SF2[SF2['Sequence number']!=''].groupby(['FlowNo.'],{
        'total_seq_no.' : gl.aggregate.COUNT('Sequence number'),
        'distinct_seq_no.' : gl.aggregate.COUNT_DISTINCT('Sequence number')
    })
recon['reconnects'] = recon['total_seq_no.'] - recon['distinct_seq_no.']
recon.head()
recon = recon[['FlowNo.','reconnects']]
SF2 = SF2.join(recon,on='FlowNo.',how='left')
len(SF2)


# In[81]:

#To identify records where reconnect check was not applied like UDP etc
SF2.fillna('reconnects',-1)


# In[ ]:

#SF2[SF2['FlowNo.']==79732]['Info']


# A lot of these reconnects can be simple retransmissions - due to out of order/timeout etcb

# ### 22-10-2016

# In[83]:



# In[15]:

print min(SF2['Time']),max(SF2['Time'])


# # 28/10/16

# Bidirectional Flowscombining all features and labels

# In[84]:


# In[85]:

SF2.save('Bidirectional_Test_Botnet_all_features.csv')


# In[ ]:

#SF2_valid_Test, SF2_test = SF2.random_split(.8, seed=5)
#SF2_valid, SF2_Test = SF2_valid_Test.random_split(.2, seed=5)
#X_Test, y_Test = SF2_Test.drop('isBot'), SF2_Test['isBot']
#X_valid, y_valid = SF2_valid_Test
#X_Test_valid, y_Test_valid = X[:3475000], y[:3475000]
#X_test, y_test = X[3475000:], y[3475000:]



# In[89]:

features = SF2.column_names()


# In[33]:


features =SF2.column_names()
features


# In[34]:


features


# In[35]:


myfeatures


# 15-11-2016

# In[36]:


SF = gl.SFrame.read_csv('Bidirectional_Train_Botnet_all_features.csv',verbose=False)


# In[37]:


len(SF)


# In[38]:


SF['Forward'] = SF.apply(lambda x: 1 if x['Source']>x['Destination'] else 0 )
temp = SF.groupby('FlowNo.',{
        'NumForward' : gl.aggregate.SUM('Forward'),
        
    })

SF = SF.join(temp,on='FlowNo.')


# In[39]:


SF.head


# In[40]:


Test = gl.SFrame.read_csv('Bidirectional_Test_Botnet_all_features.csv',verbose=False)
Test.head


# In[41]:


for col in ['Source Port','Destination Port']:
    SF[col] = SF[col].apply(lambda x: str(x))
    Test[col] = Test[col].apply(lambda x: str(x))


# In[42]:


Test['Forward'] = Test.apply(lambda x: 1 if x['Source']>x['Destination'] else 0 )
temp = Test.groupby('FlowNo.',{
        'NumForward' : gl.aggregate.SUM('Forward'),
        
    })

Test= Test.join(temp,on='FlowNo.')


# In[43]:


Test = Test.groupby('FlowNo.',{
        'Answer RRs': gl.aggregate.SELECT_ONE('Answer RRs'),
        'BytesEx' : gl.aggregate.SELECT_ONE('BytesEx'),
        'Destination' : gl.aggregate.SELECT_ONE('Destination'),
        'Destination Port' : gl.aggregate.SELECT_ONE('Destination Port'),
        'Duration' : gl.aggregate.SELECT_ONE('Duration'),
        'FPL' : gl.aggregate.SELECT_ONE('FPL'),
        'IP_Flags' : gl.aggregate.SELECT_ONE('IP_Flags'),
        'Info' : gl.aggregate.SELECT_ONE('Info'),
        'Length' : gl.aggregate.SELECT_ONE('Length'),
        'Next sequence number' : gl.aggregate.SELECT_ONE('Next sequence number'),
        'No.' : gl.aggregate.SELECT_ONE('No.'),
        'NumPackets' : gl.aggregate.SELECT_ONE('NumPackets'),
        'Protocol' : gl.aggregate.SELECT_ONE('Protocol'),
        'Protocols in frame' : gl.aggregate.SELECT_ONE('Protocols in frame'),
        'SameLenPktRatio' : gl.aggregate.SELECT_ONE('SameLenPktRatio'),
        'Sequence number' : gl.aggregate.SELECT_ONE('Sequence number'),
        'Source' : gl.aggregate.SELECT_ONE('Source'),
        'Source Port' : gl.aggregate.SELECT_ONE('Source Port'),
        'StdDevLen' : gl.aggregate.SELECT_ONE('StdDevLen'),
        'IAT' : gl.aggregate.SELECT_ONE('IAT'),
        'isNull' : gl.aggregate.SELECT_ONE('isNull'),
        'NPEx' : gl.aggregate.SELECT_ONE('NPEx'),
        'reconnects' : gl.aggregate.SELECT_ONE('reconnects'),
        'APL' : gl.aggregate.SELECT_ONE('APL'),
        'BitsPerSec' : gl.aggregate.SELECT_ONE('BitsPerSec'),
        'AvgPktPerSec' : gl.aggregate.SELECT_ONE('AvgPktPerSec'),
        'udp_Length' : gl.aggregate.SELECT_ONE('udp_Length'),
        'tcp_Flags' : gl.aggregate.SELECT_ONE('tcp_Flags'),
        'isBot' : gl.aggregate.SELECT_ONE('isBot'),
        'Time' : gl.aggregate.SELECT_ONE('Time'),
        'TCP Segment Len' : gl.aggregate.SELECT_ONE('TCP Segment Len'),
        'IOPR' : gl.aggregate.SELECT_ONE('IOPR'),
        'NumForward' : gl.aggregate.SELECT_ONE('NumForward')
    })



# In[44]:


SF = SF.groupby('FlowNo.',{
        'Answer RRs': gl.aggregate.SELECT_ONE('Answer RRs'),
        'BytesEx' : gl.aggregate.SELECT_ONE('BytesEx'),
        'Destination' : gl.aggregate.SELECT_ONE('Destination'),
        'Destination Port' : gl.aggregate.SELECT_ONE('Destination Port'),
        'Duration' : gl.aggregate.SELECT_ONE('Duration'),
        'FPL' : gl.aggregate.SELECT_ONE('FPL'),
        'IP_Flags' : gl.aggregate.SELECT_ONE('IP_Flags'),
        'Info' : gl.aggregate.SELECT_ONE('Info'),
        'Length' : gl.aggregate.SELECT_ONE('Length'),
        'Next sequence number' : gl.aggregate.SELECT_ONE('Next sequence number'),
        'No.' : gl.aggregate.SELECT_ONE('No.'),
        'NumPackets' : gl.aggregate.SELECT_ONE('NumPackets'),
        'Protocol' : gl.aggregate.SELECT_ONE('Protocol'),
        'Protocols in frame' : gl.aggregate.SELECT_ONE('Protocols in frame'),
        'SameLenPktRatio' : gl.aggregate.SELECT_ONE('SameLenPktRatio'),
        'Sequence number' : gl.aggregate.SELECT_ONE('Sequence number'),
        'Source' : gl.aggregate.SELECT_ONE('Source'),
        'Source Port' : gl.aggregate.SELECT_ONE('Source Port'),
        'StdDevLen' : gl.aggregate.SELECT_ONE('StdDevLen'),
        'IAT' : gl.aggregate.SELECT_ONE('IAT'),
        'isNull' : gl.aggregate.SELECT_ONE('isNull'),
        'NPEx' : gl.aggregate.SELECT_ONE('NPEx'),
        'reconnects' : gl.aggregate.SELECT_ONE('reconnects'),
        'APL' : gl.aggregate.SELECT_ONE('APL'),
        'BitsPerSec' : gl.aggregate.SELECT_ONE('BitsPerSec'),
        'AvgPktPerSec' : gl.aggregate.SELECT_ONE('AvgPktPerSec'),
        'udp_Length' : gl.aggregate.SELECT_ONE('udp_Length'),
        'tcp_Flags' : gl.aggregate.SELECT_ONE('tcp_Flags'),
        'isBot' : gl.aggregate.SELECT_ONE('isBot'),
        'Time' : gl.aggregate.SELECT_ONE('Time'),
        'TCP Segment Len' : gl.aggregate.SELECT_ONE('TCP Segment Len'),
        'IOPR' : gl.aggregate.SELECT_ONE('IOPR'),
        'NumForward' : gl.aggregate.SELECT_ONE('NumForward')
    })



# In[45]:


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
    if ((x['NumForward']==0) and (x['Destination'] in iplist) ) or ((x['NumForward']==x['NumPackets']) and (x['Source'] in iplist) ):
        return 1
    elif ((x['Source'] in iplist) or (x['Destination'] in iplist)) and (x['NumForward']!=0) and (x['NumForward']!=x['NumPackets']):
        return 1
    else:
        if ((x['Source'],x['Destination'])  in MasterBot ) or ((x['Destination'],x['Source'])  in MasterBot ) :
            return 1
        else:
            return 0
        

SF['isBot'] = SF[['Source','Destination','NumForward','NumPackets']].apply(lambda x: fcheckIP(x))


# In[46]:


temp = SF.groupby('FlowNo.',{
        'NumBots' : gl.aggregate.SUM('isBot')
    })
NumBotFlows = len(temp[temp['NumBots']>=1])
print NumBotFlows, NumBotFlows*1.0/len(SF['FlowNo.'].unique()) 


# In[47]:


Test['isBot'] = Test[['Source','Destination','NumForward','NumPackets']].apply(lambda x: fcheckIP(x))

temp = Test.groupby('FlowNo.',{
        'NumBots' : gl.aggregate.SUM('isBot')
    })
NumBotFlows = len(temp[temp['NumBots']>=1])
print NumBotFlows, NumBotFlows*1.0/len(Test['FlowNo.'].unique()) 


# In[48]:


len(Test[Test['isBot']==1]),len(Test)


# In[49]:


len(SF[SF['isBot']==1]),len(SF)


# In[50]:


Test.save('Bidirectional_Botnet_Test_Final_Flow_Based_Features.csv')
SF.save('Bidirectional_Botnet_Training_Final_Flow_Based_Features.csv')


# In[51]:




models = []

myfeatures = Test.column_names()
for x in ['isBot','Answer RRs','Sequence number','No.','IP_Flags','Next sequence number','Protocols in frame','Time','tcp_Flags','FlowNo.','udp_Length']:
    #print x
    #if x not in myfeatures:
        #print x 
    myfeatures.remove(x)
    


# In[52]:


myfeatures


# In[53]:


l=0
for x in iplist:
    l=l+ len(Test[(Test['IOPR']==-1) & (Test['isBot']==1) & (Test['Source']==x)])
print "Number of flows having only destination to source, and source as malicious " + str(l)


# In[54]:


l=0
for x in iplist:
    l=l+ len(SF[(SF['IOPR']==-1) & (SF['isBot']==1) & (SF['Source']==x)])
print "Number of flows having only destination to source, and source as malicious " + str(l)


# In[55]:


l=0
for x in iplist:
    l=l+ len(SF[(SF['NumForward']==0) & (SF['isBot']==1) & (SF['Source']==x)])
print "Number of flows having only destination to source, and source as malicious " + str(l)


# In[56]:


len(SF[(SF['IOPR']==0) & (SF['isBot']==1) ])


# In[57]:


len(SF[(SF['IOPR']==0) | (SF['IOPR']==-1)])


# In[58]:


len(Test[Test['IOPR']==-1]),len(Test)


# In[59]:


len(SF[SF['IOPR']==-1]),len(SF)


# In[60]:


for x in ['Source','Source Port','Destination','Destination Port','TCP Segment Len','Length']:
    myfeatures.remove(x)
    


# In[61]:


myfeatures1 = ['APL','IOPR','BitsPerSec','Duration']


# In[62]:


myfeatures.remove('isNull')
myfeatures.remove('Info')


# In[63]:


len(Test[Test['reconnects']==''])


# In[64]:


myfeatures.remove('reconnects')


# In[65]:


myfeatures.remove('IOPR')


# In[66]:


myfeatures


# In[67]:


len(Test[Test['isBot']==0]),len(Test[Test['isBot']==1])


# In[68]:


len(SF[SF['isBot']==0]),len(SF[SF['isBot']==1])


# In[69]:


SF = SF[SF['NumPackets']>1]
Test = Test[Test['NumPackets']>1]


# In[70]:


SF = gl.cross_validation.shuffle(SF)
Folds = gl.cross_validation.KFold(SF,5)
j=0
for train,val in Folds:
    model = gl.boosted_trees_classifier.create(train,features=myfeatures,target='isBot',validation_set=val,verbose = False,max_iterations=100)
    models.append(model)
    print "Done",j
    j=j+1
    
pred = []
for model in models:
    temp = list(model.predict(Test))
    pred.append(temp)
    
final = []
for i in range(len(Test)):
    count = 0
    for j in range(5):
        if pred[j][i] ==1:
            count += 1
    if count>2:
        final.append(1)
    else:
        final.append(0)
        
print gl.toolkits.evaluation.auc(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.accuracy(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.confusion_matrix(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.f1_score(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.log_loss(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.precision(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.recall(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.roc_curve(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.roc_curve(Test['isBot'],gl.SArray(final))


# In[71]:


models = []
    
#LOGISTIC REGRESSION
j=1
for train,val in Folds:
    model = gl.logistic_classifier.create(train,features=myfeatures,target='isBot',validation_set=val,verbose = False,max_iterations=100)
    models.append(model)
    print "Done",j
    j=j+1
    
pred = []
for model in models:
    temp = list(model.predict(Test))
    pred.append(temp)
    
final = []
for i in range(len(Test)):
    count = 0
    for j in range(5):
        if pred[j][i] ==1:
            count += 1
    if count>2:
        final.append(1)
    else:
        final.append(0)
        
print gl.toolkits.evaluation.auc(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.accuracy(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.confusion_matrix(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.f1_score(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.log_loss(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.precision(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.recall(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.roc_curve(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.roc_curve(Test['isBot'],gl.SArray(final))


# In[72]:


models = []
SF = gl.cross_validation.shuffle(SF)
Folds = gl.cross_validation.KFold(SF,5)
j=0
for train,val in Folds:
    model = gl.random_forest_classifier.create(train,features=myfeatures,target='isBot',validation_set=val,verbose = False,max_iterations=100)
    models.append(model)
    print "Done",j
    j=j+1
    
pred = []
for model in models:
    temp = list(model.predict(Test))
    pred.append(temp)
    
final = []
for i in range(len(Test)):
    count = 0
    for j in range(5):
        if pred[j][i] ==1:
            count += 1
    if count>2:
        final.append(1)
    else:
        final.append(0)
        
print gl.toolkits.evaluation.auc(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.accuracy(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.confusion_matrix(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.f1_score(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.log_loss(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.precision(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.recall(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.roc_curve(Test['isBot'],gl.SArray(final))
print gl.toolkits.evaluation.roc_curve(Test['isBot'],gl.SArray(final))


# In[73]:


SF.save('FinalTrain.csv')
Test.save('FinalTest.csv')


# In[74]:


SF.column_names()


# In[76]:


len(SF[SF['IOPR']==-1])


# In[77]:


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


# In[78]:


Test.add_column(gl.SArray(final),'Predicted_Label')


# In[79]:



truePosIPs = Test[(Test['isBot']==1) & (Test['Predicted_Label']==1)]['Source'].unique()
i=0
for x in truePosIPs:
    if x in iplist:
        print x
        i=i+1
    else:
        print "Not in Malicious IP List " + x
print i



# In[80]:


falseNegIPs = Test[(Test['isBot']==1) & (Test['Predicted_Label']==0)]['Source'].unique()
len(falseNegIPs)

i=0
for x in falseNegIPs:
    if x in iplist:
        print x
        i=i+1
    else:
        print "Not in Malicious IP List " + x
print i

BotsInTrain = SF[(SF['isBot']==1)]['Source'].unique()

i=0
for x in falseNegIPs:
    if x in BotsInTrain:
        print x + " in both train and test, still not detected"
    else:
        i=i+1
print str(i) + " Bot IPs present in test, not in train, undetected "

i=0
for x in truePosIPs:
    if x in BotsInTrain:
        print x + " in both train and test, detected"
    else:
        i=i+1
print str(i) + " Bot IPs present in test, not in train, still detected => Novelty Detection "

