
#================ES================
ELASTIC_IP      = '[ES_IP]'
ELASTIC_PORT    = '[ES_PORT]'
ELASTIC_INDEX   = '[ES_INDEX]'
ELASTIC_TYPE    = '[ES_TYPE]'

CURL            = 'curl -XPOST "http://'+ELASTIC_IP+':'+ELASTIC_PORT+'/'+ELASTIC_INDEX+'/'+ELASTIC_TYPE+'?pretty" -H "Content-Type: application/json" --data-binary @report.json'

#================MONITOR================
#json file download folder

DIR = r'[folder path]'
