#=============================================================================
# Imports
#=============================================================================
from os import environ
import json
import boto3
import datetime
import math
import time
import gzip

#=============================================================================
# Constants
#=============================================================================
API_CALL_NUM_RETRIES = 3
MAX_SAMPLED_ITEMS = 500

#=============================================================================
# Variables
#=============================================================================
waf = boto3.client('waf')
stack_name = environ['STACK_NAME']
web_acl_id = environ['WEB_ACL_ID']
waf_log_bucket_name = environ['WAF_LOG_BUCKET']
start_str = ''
end_str = ''


#==========================
# Lambda entry point
#==========================
def lambda_handler(event, context):

    #-----------------------------------------------
    # prep
    #-----------------------------------------------
    blocked_requests = event['BlockedRequests']
    cloudfront_log_filename = event['CloudfrontLogFilename']
    web_acl_name = get_web_acl_name(web_acl_id)

    #-----------------------------------------------
    # get args needed for get-sampled-requests
    #-----------------------------------------------
    # get (naive=utc) time interval surrounding the whole set of blocked
    # requests
    search_interval_dt = get_surrounding_interval_datetime(blocked_requests)
    # get rule info for the web-acl we're dealing with
    rules_info = get_rules_info(web_acl_id)
    blocking_rule_ids = get_blocking_rule_ids(rules_info)

    #-----------------------------------------------
    # start constructing error logs
    #-----------------------------------------------
    num_blocked_requests = len(blocked_requests)
    times_of_blocked_requests = get_request_ips_and_times(blocked_requests)
    search_interval_string = get_time_interval_string(search_interval_dt)
    error_dict = {
        'CloudfrontLogFilename': cloudfront_log_filename,
        'NumOfBlockedRequests': num_blocked_requests,
        'BlockedRequests': times_of_blocked_requests,
        'SearchInterval': search_interval_string,
        'NumOfMatchedSampledRequests': 0,
        'MatchedSampledRequests': {}
    }

    #-----------------------------------------------
    # get-sampled-requests and process results
    #-----------------------------------------------
    for blocking_rule_id in blocking_rule_ids:
        rule_metric_name = rules_info[blocking_rule_id]['MetricName']
        error_dict['MatchedSampledRequests'][rule_metric_name] = {
            'NumOfMatchedRequests': 0,
            'MatchedRequests': []
        }
        results = get_sampled_requests(web_acl_id, blocking_rule_id,
                                       search_interval_dt, MAX_SAMPLED_ITEMS)
        sampled_requests = results['SampledRequests']
        if sampled_requests:  # ignore empty sets of requests!
            # get the time interval sampled
            sampled_interval_dt = results['TimeWindow']
            sampled_interval_string = get_time_interval_string(
                sampled_interval_dt)
            # work through blocked requests, looking for matching sampled requests
            for blocked_request in blocked_requests:
                matched_requests = []
                for sampled_request in sampled_requests or []:
                    if sampled_request_matches_blocked_request(
                            sampled_request, blocked_request):
                        # create a log entry for the blocked request and
                        # matching sampled request
                        create_log_entry(sampled_request, web_acl_name,
                                         rule_metric_name)
                        # add info to error_dict
                        request_ip = sampled_request['Request']['ClientIP']
                        request_time = get_request_time_string(sampled_request)
                        error_dict['MatchedSampledRequests'][rule_metric_name][
                            'MatchedRequests'].append({
                                'MatchedRequest': {
                                    'MatchedRequestIP': request_ip,
                                    'MatchedRequestTime': request_time
                                }
                            })
                        error_dict['MatchedSampledRequests'][rule_metric_name][
                            'NumOfMatchedRequests'] += 1
                        error_dict['NumOfMatchedSampledRequests'] += 1
                        error_dict['SampledInterval'] = sampled_interval_string
                        # once sampled request logged, no need to look at again
                        matched_requests.append(sampled_request)
                # slice sampled_requests to remove matched_requests before
                # next iteration
                sampled_requests[:] = [
                    x for x in sampled_requests if x not in matched_requests
                ]
    # check if insufficient sampled requests (NB. can only say if there are definitely
    # insufficient - can't guarantee there are definitely sufficient because of rounding times!)
    if error_dict['NumOfBlockedRequests'] > error_dict['NumOfMatchedSampledRequests']:
        create_error_log(error_dict, web_acl_name, cloudfront_log_filename)


#==========================
# Helper functions
#==========================


#==========================
# creating/uploading logs
#==========================
#----------------------------------------------
# create log entry for sampled blocked request
#----------------------------------------------
def create_log_entry(sampled_request, web_acl_name, rule_metric_name):
    # folder info - need datestamp from current time
    naive_time = datetime.datetime.now(
    )  # already naive and no need to truncate
    datestamp = naive_time.strftime('%Y%m%d')
    foldername = 'waf_logs/stack=' + stack_name + '/datestamp=' + datestamp \
            + '/rule=' + rule_metric_name + '/'
    # filename info:
    dt = sampled_request['Timestamp']
    # want utc i.e. remove any local timezone stuff by making naive, but no need to truncate
    naive_time = aware_to_naive_datetime(dt, truncated=False)
    # replace with string
    unixtime = str(
        int(
            time.mktime(naive_time.timetuple()) * 1000 +
            naive_time.microsecond / 1000))
    filename = 'request_blocked_at_' + unixtime
    # replace sampled_request['Timestamp'] with unixtime so json serializable
    sampled_request['Timestamp'] = unixtime
    # file contents = dictionary
    dict = {
        'WebACLName': web_acl_name,
        'BlockingRule': rule_metric_name,
        'SampledRequestInfo': sampled_request,
    }
    # create file to upload
    file_to_upload = create_gz_from_json(dict, filename)
    # and publish to s3
    upload_file_to_s3(file_to_upload, waf_log_bucket_name,
                      foldername + filename + '.json.gz')
    # change sampled_request['Timestamp'] back to its original value for future
    # comparisons (now that we are processing requests in groups, a sampled request
    # might get looked at multiple times)
    sampled_request['Timestamp'] = dt


#----------------------------------------------
# create error log for 'missing' sampled requests
#----------------------------------------------
def create_error_log(error_dict, web_acl_name, cloudfront_log_filename):
    # folder info - need datestamp from current time
    naive_time = datetime.datetime.now(
    )  # already naive and no need to truncate
    datestamp = naive_time.strftime('%Y%m%d')
    foldername = 'waf_logs/stack=' + stack_name + '/datestamp=' + datestamp \
            + '/error_logs/'
    # filename info - need timestamp
    unixtime = str(
        int(
            time.mktime(naive_time.timetuple()) * 1000 +
            naive_time.microsecond / 1000))
    filename = 'error_log_created_at_' + unixtime
    print(filename)
    # create file to upload
    file_to_upload = create_gz_from_json(error_dict, filename)
    # and publish to s3
    upload_file_to_s3(file_to_upload, waf_log_bucket_name,
                      foldername + filename + '.json.gz')


#------------------------------------------------------------------------
# Saves string to .gz file
#------------------------------------------------------------------------
def create_gz_from_json(dict, filename):
    json_str = json.dumps(dict)
    json_bytes = json_str.encode('utf-8')
    source_filename = '/tmp/' + filename + '.json.gz'
    with gzip.GzipFile(source_filename, 'w') as fout:
        fout.write(json_bytes)
    return source_filename


#------------------------------------------------------------------------
# Upload file to s3 bucket
#------------------------------------------------------------------------
def upload_file_to_s3(source_filename, bucket_name, destination_filename):
    s3_client = boto3.client('s3')
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            s3_client.upload_file(source_filename, bucket_name,
                                  destination_filename)
        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print('[upload_file_to_s3] Retrying in %d seconds...' % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print('[upload_file_to_s3] Failed ALL attempts to call API')


#==========================
# Date/time functions
#==========================
#------------------------------------------------------------------------
# Returns a single datetime object from the date/time of the cloudfront log
#------------------------------------------------------------------------
def get_datetime(date, time):
    dt_string = date + ' ' + time

    return datetime.datetime.strptime(dt_string, '%Y-%m-%d %H:%M:%S')


#------------------------------------------------------------------------
# Returns a time interval in datetime format containing times of set of
# blocked requests
#------------------------------------------------------------------------
def get_surrounding_interval_datetime(blocked_requests):
    req = blocked_requests[0]
    start_date_time = get_datetime(req['ReqDate'], req['ReqTime'])
    end_date_time = get_datetime(req['ReqDate'], req['ReqTime'])
    # broaden out to include other blocked requests
    for blocked_request in blocked_requests:
        blocked_date = blocked_request['ReqDate']
        blocked_time = blocked_request['ReqTime']
        dt = get_datetime(blocked_date, blocked_time)
        start_date_time = min(start_date_time, dt)
        end_date_time = max(end_date_time, dt)
    # include 2s either side in case of rounding/truncation errors
    minute_delta = datetime.timedelta(seconds=2)
    interval_start_time = start_date_time - minute_delta
    interval_end_time = min(end_date_time + minute_delta,
                            datetime.datetime.now())
    return {'StartTime': interval_start_time, 'EndTime': interval_end_time}


#------------------------------------------------------------------------
# Converts a time interval in datetime format to string format
#------------------------------------------------------------------------
def get_time_interval_string(dt_interval):
    interval_start_time = dt_interval['StartTime']
    interval_end_time = dt_interval['EndTime']
    start_string = interval_start_time.strftime('%Y-%m-%d %H:%M:%S')
    end_string = interval_end_time.strftime('%Y-%m-%d %H:%M:%S')
    return {'StartTime': start_string, 'EndTime': end_string}


#------------------------------------------------------------------------
# construct string datetime from sampled request
#------------------------------------------------------------------------
def get_request_time_string(sampled_request):
    sample_dt = sampled_request['Timestamp']
    naive_trunc_sample_dt = aware_to_naive_datetime(sample_dt, truncated=True)
    return naive_trunc_sample_dt.strftime('%Y-%m-%d %H:%M:%S')


#------------------------------------------------------------------------
# Converts 'aware' datetime to 'naive' datetime with microsecond accuracy
# (default) or truncated
#------------------------------------------------------------------------
def aware_to_naive_datetime(aware_dt, truncated=False):
    # extract components of time from sampled request, and create a datetime
    # to compare with logged datetime
    year = aware_dt.year
    month = aware_dt.month
    day = aware_dt.day
    hour = aware_dt.hour
    minute = aware_dt.minute
    second = aware_dt.second
    micro = aware_dt.microsecond
    # create a new naive datetime (TODO: use pytz idc)
    if truncated:
        return datetime.datetime(year, month, day, hour, minute, second)
    else:
        return datetime.datetime(year, month, day, hour, minute, second, micro)


#==========================
# web acl/rule functions
#==========================
#---------------------------------------------------------------------------------
# Returns an dict of all rules associated with given web-acl, and their properties
#---------------------------------------------------------------------------------
def get_rules_info(web_acl_id):
    response = {}
    rule_id = ''
    rule_type = ''
    rule_name = ''
    rule_metric_name = ''
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            rules_ids_types = waf.get_web_acl(
                WebACLId=web_acl_id)['WebACL']['Rules']
            for rule_id_type in rules_ids_types:
                rule_id = rule_id_type['RuleId']
                rule_type = rule_id_type['Type']
                if rule_type == 'REGULAR':
                    rule = waf.get_rule(RuleId=rule_id)['Rule']
                    rule_name = rule['Name']
                    rule_metric_name = rule['MetricName']
                elif rule_type == 'RATE_BASED':
                    # flood protection not used as of July 2018, since usually failed
                    # to create rule, so if there's a run-time error with this method,
                    # check if it's looking for a rule that, although listed under
                    # the web acl, doesn't actually exist!!
                    rule = waf.get_rate_based_rule(RuleId=rule_id)['Rule']
                    rule_name = rule['Name']
                    rule_metric_name = rule['MetricName']
                # else:
                # do nothing: Default_Action has no associated rule_type (as it's not
                # actually a proper rule...)... but keep code below for testing
                # rule_name = 'Default_Action'
                # rule_metric_name = 'Default_Action'
                response[rule_id] = {
                    'Type': rule_type,
                    'Name': rule_name,
                    'MetricName': rule_metric_name
                }
        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print('[get_rule_ids] Retrying in %d seconds...' % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print('[get_rule_ids] Failed ALL attempts to call API')

    return response


#------------------------------------------------------------------------
# Returns the name of a web-acl given its id
#------------------------------------------------------------------------
def get_web_acl_name(web_acl_id):
    web_acl_name = None
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            web_acl_name = waf.get_web_acl(
                WebACLId=web_acl_id)['WebACL']['Name']
        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print('[get_web_acl_name] Retrying in %d seconds...' % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print('[get_web_acl_name] Failed ALL attempts to call API')

    return web_acl_name


#------------------------------------------------------------------------
# Returns an array of all blocking rules associated with given web acl
#------------------------------------------------------------------------
def get_blocking_rule_ids(rules_info):
    response = []
    rule_ids = rules_info.keys()
    for rule_id in rule_ids:
        rule_name = rules_info[rule_id]['Name']
        if rule_name.upper().find('WHITELIST') < 0:
            response.append(rule_id)

    # if need to add in Default_Action for testing purposes
    # response.append('Default_Action')

    return response


#==========================
# sampled-requests functions
#==========================


#------------------------------------------------------------------------
# get-sampled-requests for given rule and request date/time -
# need to think about how to use number of requests from which the
# sample is drawn, since we can check if our sample is 'complete'!!
#------------------------------------------------------------------------
def get_sampled_requests(web_acl_id, rule_id, time_window, max_sampled_items):
    response = None
    print("getting sampled requests for rule_id = " + rule_id)
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_sampled_requests(
                WebAclId=web_acl_id,
                RuleId=rule_id,
                TimeWindow=time_window,
                MaxItems=max_sampled_items)
        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print('[waf_get_sampled_requests] Retrying in %d seconds...' %
                  (delay))
            time.sleep(delay)
        else:
            break
    else:
        print('[get_sampled_requests] Failed ALL attempts to call API')

    return response


#------------------------------------------------------------------------
# check an individual sampled request against the blocked request
#------------------------------------------------------------------------
def sampled_request_matches_blocked_request(sampled_request, blocked_request):
    sample_dt = sampled_request['Timestamp']
    naive_trunc_sample_dt = aware_to_naive_datetime(sample_dt, truncated=True)
    sample_ip = sampled_request['Request']['ClientIP']
    sample_method = sampled_request['Request']['Method']
    sample_uri = sampled_request['Request']['URI']

    blocked_date = blocked_request['ReqDate']
    blocked_time = blocked_request['ReqTime']
    blocked_ip = blocked_request['ReqIP']
    blocked_method = blocked_request['ReqMethod']
    blocked_uri = blocked_request['ReqUri']

    blocked_dt = get_datetime(blocked_date, blocked_time)
    seconds_delta = datetime.timedelta(seconds=1)

    return (blocked_dt == naive_trunc_sample_dt or \
            blocked_dt + seconds_delta == naive_trunc_sample_dt or \
            blocked_dt - seconds_delta == naive_trunc_sample_dt) and \
            blocked_ip == sample_ip and blocked_method == sample_method


#------------------------------------------------------------------------
# construct list of times and ips from list of blocked requests
#------------------------------------------------------------------------
def get_request_ips_and_times(blocked_requests):
    response = []
    for blocked_request in blocked_requests:
        response.append({
            'BlockedRequest': {
                'BlockedRequestTime':
                blocked_request['ReqDate'] + ' ' + blocked_request['ReqTime'],
                'BlockedRequestIP':
                blocked_request['ReqIP']
            }
        })
        return response
