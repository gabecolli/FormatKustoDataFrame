from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from azure.monitor.ingestion import LogsIngestionClient
import os
from dotenv import load_dotenv
import datetime
from datetime import timedelta
import pandas as pd
import requests
load_dotenv()

customerId = "workspaceID"
shared_key = "key"


query = '''let timeRangeStart = now(-3d);
let timeRangeEnd = now();
InsightsMetrics
| where TimeGenerated >= timeRangeStart and TimeGenerated <= timeRangeEnd
| summarize heartbeat_per_hour=count() by bin_at(TimeGenerated, 1h, timeRangeStart), Computer
| extend available_per_hour=iff(heartbeat_per_hour>0, true, false)
| summarize total_available_hours=countif(available_per_hour==true) by Computer
| extend total_number_of_buckets=round((timeRangeEnd-timeRangeStart)/1h)
| extend availability_rate=total_available_hours*100/total_number_of_buckets
| join (
    InsightsMetrics
    | where Name == 'UtilizationPercentage'
    | project-rename CPU_Util = Val
    | project-away TenantId, TimeGenerated, SourceSystem, Origin, Namespace, Tags, AgentId, _ResourceId, Type
) on Computer
| join (
    InsightsMetrics
    | where Name == 'AvailableMB'
    | project-rename Free_MemoryMB = Val
    | project-away TenantId, TimeGenerated, SourceSystem, Origin, Namespace, Tags, AgentId, _ResourceId, Type
) on Computer
| join (
    InsightsMetrics
    | where Name == 'ReadBytesPerSecond'
    | project-rename Network_ReadBytesPerSecond = Val
    | project-away TenantId, TimeGenerated, SourceSystem, Origin, Namespace, Tags, AgentId, _ResourceId, Type
) on Computer
| join (
    InsightsMetrics
    | where Name == 'FreeSpacePercentage'
    | project-rename FreeSpace = Val
    | project-away TenantId, TimeGenerated, SourceSystem, Origin, Namespace, Tags, AgentId, _ResourceId, Type
) on Computer
| join (
    InsightsMetrics
    | where Name == 'TransfersPerSecond'
    | project-rename TransferPerSecond = Val
    | project-away TenantId, TimeGenerated, SourceSystem, Origin, Namespace, Tags, AgentId, _ResourceId, Type
) on Computer'''

credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)




logs_client = LogsQueryClient(credential)
response = logs_client.query_workspace(
        workspace_id=os.environ['WORKSPACEID'],
        query=query,
        timespan=timedelta(days=1)
                    )
data = response.tables
data_list = []
for table in data:
    df = pd.DataFrame(data=table.rows, columns=table.columns)
    df = df.drop(columns=["Computer1", "Computer2", "Computer3", "Computer4", "Computer5"])
    computer_column = "Computer"
    df[computer_column] = df[computer_column].drop_duplicates()
    df.dropna(inplace=True)
    data_list.append(df)
json_data = data_list[0].to_json(orient="records")
#

#need to get the request object encoded into utf-8 then get the length of that byte array. 
#that is the content length to be used in the signature
import hashlib
import hmac
import base64




json_utf8 = json_data.encode('utf-8')


current_datetime = datetime.datetime.now(datetime.timezone.utc)
rfc1123_datetime = current_datetime.strftime('%a, %d %b %Y %H:%M:%S GMT')


def build_signature(customer_id, shared_key, date, method, content_type, resource, json_payload):
    x_headers = "x-ms-date:" + date
    string_to_hash = method + "\n" + str(len(json_payload)) + "\n" + content_type + "\n" + x_headers + "\n" + resource

    bytes_to_hash = string_to_hash.encode('utf-8')
    key_bytes = base64.b64decode(shared_key)

    hmac_sha256 = hmac.new(key_bytes, bytes_to_hash, hashlib.sha256)
    calculated_hash = hmac_sha256.digest()
    encoded_hash = base64.b64encode(calculated_hash).decode('utf-8')

    authorization = 'SharedKey {}:{}'.format(customer_id, encoded_hash)
    return authorization



auth_sig = build_signature(customer_id="workspaceID goes here",
                shared_key="workspacekey goes here",
                date=rfc1123_datetime, method= "POST", content_type="application/json",
                resource="/api/logs",
                json_payload=json_utf8
                )




TimeStampField = ""
contentType = "application/json"
resource = "/api/logs"

uri = f"https://{customerId}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"

headers = {
        "Authorization" : auth_sig,
        "Log-Type" : "CustomLogName",
        "x-ms-date" : rfc1123_datetime,
        "time-generated-field" : TimeStampField,
        "Content-Type" : contentType
    }
response = requests.post(url=uri,data=json_data,headers=headers)
print(response)
