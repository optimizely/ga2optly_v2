#GA Segment Importer for Optimizely
'''
KNOWN LIMITATIONS:

1. Only works with lists smaller than 180,000 ids (Capped at that limit because of 5mb uploaded audience limit).  Consider migrating to DCP.
'''

#---------------Python Modules-----------------------------
import time
import re
import urllib
import urllib2
import json
import base64
import webapp2
import httplib2
import hashlib
import hmac
import pickle
from Crypto.Cipher import AES
from Crypto import Random
from oauth2client import client
from apiclient.discovery import build
from google.appengine.ext import ndb

import config


#-----------------Database Entities--------------------------

class Project_info(ndb.Model): #key is optly project id
    project_id = ndb.IntegerProperty(indexed=True) #Optly project id
    credentials = ndb.BlobProperty(indexed=True) #pickeled and then ENCRYPTED GA credentials object
    api_token = ndb.BlobProperty(indexed=True) #ENCRYPTED optly standard API token (used for cron)
    dimension_id = ndb.StringProperty(indexed=False) #ga dimension index number for where _ga cookie value is stored
    view_id = ndb.StringProperty(indexed=False) #ga view id (where we're retrieving ga data from)
    interval = ndb.StringProperty(indexed=False) #number of days in the past we should look for ga data
    update_cadence = ndb.IntegerProperty(indexed=False) #number of seconds between cron updates being allowed to run for lists in this project
    update_cadence_str = ndb.StringProperty(indexed=False) #string expressing number of minutes, hours or days between updates
    last_cron_end = ndb.IntegerProperty(indexed=False, default=0) #epoch timestamp for last time cron completed for this project

class Segment_info(ndb.Model): #key is "PROJECT_ID:OPTLY_ID"
    segment_name = ndb.StringProperty(indexed=False) #name of GA segment
    ga_id = ndb.StringProperty(indexed=False) #ga segment id
    optly_id = ndb.IntegerProperty(indexed=False) #optly uploaded list id
    project_id = ndb.IntegerProperty(indexed=True) #optly project id
    auto_update = ndb.BooleanProperty(indexed=True, default=False) #is auto-update enabled for this segment?

#--------------Google Oauth, encryption, and environment-----------------------------
#get config options from config.py
configuration = config.get_settings("Prod") #gets environment variables.  Options are "Dev" and "Prod"

#google oauth objects
flow = client.flow_from_clientsecrets(
    'client_secrets.json',
    scope='https://www.googleapis.com/auth/analytics.readonly',
    redirect_uri=configuration.redirect_uri
)
flow.params['access_type'] = 'offline'

client_secret = configuration.client_secret #supply Optimizely Canvas App client_secret

#AES encryption method thanks to http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256 (author http://stackoverflow.com/users/696326/marcus)
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AESCipher:
    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

obj = AESCipher(configuration.encryption_key)

#--------------CSS and HTML Layouts for the web app--------

#define CSS styling for web app
CSS = '<html><head><script src="https://ajax.googleapis.com/ajax/libs/jquery/2.2.2/jquery.min.js"></script><link rel="stylesheet" href="//d2uaiq63sgqwfs.cloudfront.net/8.0.0/oui.css"><link rel="stylesheet" href="//d2uaiq63sgqwfs.cloudfront.net/8.0.0/oui-extras.css"></head><body style="padding-left:50px;padding-top:30px">'

#define HTML templates for pages in the web app
MAIN_PAGE_TEMPLATE = CSS + """\
    %s
    <div><h1>Welcome to the Google Analytics Segment Importer for Optimizely</h1></div>
    <p>
        Step 1:  Authenticate with Google:  %s
    </p>
    <p>
        Step 2:  Configure Google Analytics Settings:  %s
    </p>
    <p>
        Step 3:  Import Google Analytics Segments:  %s
    </p>
    <p>
        Step 4:  Configure Automatic Updates:  %s
    </p>
    <a href="https://docs.google.com/document/d/1bEmp4oMT4r69iDhCW3OFQs8FpDPDENHLFyMRKHSCm10/" target="_blank">See here for app usage instructions</a>
    <div>Version 2.0</div>
  </body>
</html>
"""

GENERIC_PAGE_TEMPLATE = CSS + """\
    %s
    <p>
    <a href='/'>Head back home!</a>
    </p>
    </body>
</html>
"""

UPDATE_PAGE_TEMPLATE = CSS + """\
    <h2>Updates made:</h2>
    %s
    <p><a href='/schedule'>Back to Auto-update settings</a></p>
    <p><a href='/'>Back to top page</a></p>
    </body>
</html>
"""


SCHEDULE_PAGE_TEMPLATE_1 = CSS + """\
    <h1>Auto-update settings</h1>
    <h2>Admin API Token</h2>
    <p>
        <form action='/settings_conf' method='post'>Enter Admin API Token: <input type='text' name='api_token' required>
    <p>
        Enter update cadence: <input type='text' name='update_cadence' required>
        <select name='unit'>
            <option value='hours'>hours</option>
            <option value='days'>days</option>
        </select>
        <br>
        Note:  Uploaded Audience data may take up to 4 hours to propagate and be available for targeting.
    </p>
    <p>
    <input type='submit' value='Submit'>
    </p>
    </form>
    </p>
    <a href='/'>Back to top page</a>
    </body>
</html>
"""
SCHEDULE_PAGE_TEMPLATE_2 = CSS + """\
    <h1>Auto-update Settings</h1>
    <h2>Last update ran at: %s GMT</h2>
    <h2>Admin API Token</h2>
    <p>
    <p>Last 6 characters of Current API Token = <b>%s</b></p>
    <p>
    <form action='/settings_conf' method='post'>Enter New Admin API Token: <input type='text' name='api_token'>
    </p>
    <p>
    Current update cadence = <b>%s</b>
    </p>
        <p>
        Enter new update cadence: <input type='text' name='update_cadence'>
        <select name='unit'>
            <option value='hours'>hours</option>
            <option value='days'>days</option>
        </select>
        <br>
        Note:  Uploaded Audience data may take up to 4 hours to propagate and be available for targeting.
    </p>

    <input type='submit' value='Submit'>
    </p>
    </form>
    </p>
    <h2>Auto-update enabled:</h2>
    %s
    <h2>Auto-update disabled:</h2>
    %s
    <a href='/'>Back to top page</a>
    </body>
</html>
"""

SETTINGS_PAGE_TEMPLATE = CSS + """\
    <h1>Set up importing preferences!</h1>
    <form action='/settings_conf' method='post'>
        <p>GA View:
            <select name="view_id" required>
                %s
            </select>
        </p>
        %s
        %s
        <p><input type='submit' value='Submit'></p></form>
    <p><a href='/'>Back to top page</a></p>
    </body>
</html>
"""

CREATE_PAGE_TEMPLATE = CSS + """\
    <h2>Updates made:</h2>
    %s
    <br>
    Note:  Uploaded Audience data may take up to 4 hours to propagate and be available for targeting.
    <p><a href="/select">Select another segment</a></p>
    <p><a href='/'>Back to top page</a></p>
    </body>
</html>
"""

SELECT_PAGE_TEMPLATE = CSS + """\
    <h2>Please select a segment to import:</h2>
    <form action='/create' method='post'>
    %s
    <input type='submit' value='Submit'>
    </form>
    <p><a href='/'>Back to top page</a></p>
    </body>
</html>
"""

#-------------------API Methods-----------------------------
#define method for verifying context payload
def verify_context(query_string):
    signed_request = urllib.unquote(query_string.split("signed_request=")[1]).decode('utf8').split('.')
    hashed_base64_context = signed_request[0]
    unhashed_base64_context = signed_request[1]
    HMAC_hash = hmac.new(client_secret, unhashed_base64_context, digestmod=hashlib.sha256).hexdigest().lower()
    b64encoded_hash = base64.b64encode(HMAC_hash)
    if b64encoded_hash == hashed_base64_context:
        return json.loads(base64.b64decode(unhashed_base64_context))
    else:
        return False

#let's define our API methods
def rest_api_put(project_id, url, data, token_type, token):

    if token_type == "standard":
        headers = {'Token': token, 'Content-type': 'application/json'}
    elif token_type == "bearer":
        headers = {'Authorization': "Bearer " + token, 'Content-type': 'application/json'}

    opener = urllib2.build_opener(urllib2.HTTPHandler)
    request = urllib2.Request(url, data=json.dumps(data), headers=headers)
    request.get_method = lambda: 'PUT'
    api_response = opener.open(request, timeout=20)
    response_data = json.loads(api_response.read())
    return response_data

def rest_api_post(project_id, url, data, session_token):
    api_request = urllib2.Request(url)

    api_request.add_header("Content-type", "application/json")
    api_request.add_header("Authorization", "Bearer " + session_token)
    api_response = urllib2.urlopen(api_request, json.dumps(data), 20)
    response_data = json.loads(api_response.read())
    return response_data

def rest_api_get(project_id, url, token_type, token):
    #create request object
    api_request = urllib2.Request(url)
    api_request.add_header("Content-type", "application/json")

    #check token type
    if token_type == "standard":
        api_request.add_header("Token", token)
    elif token_type == "bearer":
        api_request.add_header("Authorization", "Bearer " + token)

    api_response = urllib2.urlopen(api_request, None, 20)
    response_data = json.loads(api_response.read())
    return response_data

def GetGAIds(current_project_id, segment_id, clear_credentials):
    #get google oauth credentials and build the service object
    project_info = ndb.Key(Project_info, current_project_id).get()

    http_auth = clear_credentials.authorize(httplib2.Http())
    analytics = build('analytics', 'v3', http=http_auth)

    #handle pagination
    list_content = []
    firstRun = True
    params = {'ids':project_info.view_id,
            'start_date':project_info.interval,
            'end_date':'today',
            'metrics':'ga:visits',
            'dimensions':project_info.dimension_id,
            'segment':segment_id,
            'start_index':1,
            'max_results':10000}

    while firstRun == True or response.get('nextLink'):
        if firstRun == False:
            params['start_index'] = int(params['start_index']) + int(params['max_results'])

        response = analytics.data().ga().get(**params).execute()
        firstRun = False

        if response['totalResults'] > 0:
            for row in response['rows']:
                list_content.append(row[0])

    return list_content

def ClearCredentials(current_project_id):
    #get parent project_info
    project_info = ndb.Key(Project_info, current_project_id).get()

    encrypt_credentials = project_info.credentials
    pickled_credentials = obj.decrypt(encrypt_credentials)
    clear_credentials = pickle.loads(pickled_credentials)

    return clear_credentials

#-----------------Web App Page Request Handlers--------------



class MainPage(webapp2.RequestHandler):
    def get(self):
        #deal with verifying Optly context, refreshing signed_request cookie if query is present (because canvas app just loaded)
        if "signed_request" in self.request.query_string:
            self.response.set_cookie('signed_request', self.request.query_string, httponly=True)
            context = verify_context(self.request.query_string)
        else:
            context = verify_context(self.request.cookies.get('signed_request'))
        if context != False:

            #deal with tokens and stuff
            token = context['context']['client']['access_token']
            project_id = context['context']['environment']['current_project']

            #check for project_object and create if it doesn't exist
            project_info = ndb.Key(Project_info, project_id).get()

            if project_info == None:
                project_info = Project_info()
                project_info.project_id = project_id
                project_info.key = ndb.Key(Project_info, project_id)
                project_info.put()

            #configure UI
            step_3 = '<a href="/select">Import</a>'
            step_4 = '<a href="/schedule">Configure</a>'

            #start auth flow with popout link to Google
            auth_uri = flow.step1_get_authorize_url() + "&approval_prompt=force"

            #check to see if they've already done Google OAuth
            if project_info.credentials == None:
                #append JS method to reload page after google oauth window closes
                step_0 = '<script>var FocusMethod = function(){location.reload()}; $(document).ready(function() { $(window).one("focus", FocusMethod); } );</script>'
                step_1 = "<a href='%s'>Authenticate with Google</a>" % ('javascript:window.open("%s", "Google Account", "location=0,status=0,scrollbars=0, resizable=0, directories=0, toolbar=0, titlebar=1, width=800, height=800");' % (auth_uri))
                step_2 = step_3 = step_4 = ""
            else:
                step_0 = ""
                step_1 = "Authenticated!  <a href='%s'>Re-authenticate?</a>" % ('javascript:window.open("%s", "Google Account", "location=0,status=0,scrollbars=0, resizable=0, directories=0, toolbar=0, titlebar=1, width=800, height=800");' % (auth_uri))

                #check to see if they've already configure GA settings
                if project_info.view_id == None or project_info.interval == None or project_info.dimension_id == None:
                    step_2 = '<a href="/settings">Configure settings</a>'
                    step_3 = step_4 = ""
                else:
                    step_2 = '<a href="/settings">Change settings</a>'

            self.response.write(MAIN_PAGE_TEMPLATE % (step_0, step_1, step_2, step_3, step_4))

        else:
            self.response.write(MAIN_PAGE_TEMPLATE % ("<div>Unauthenticated user, no soup for you!</div>"))


class OAuthPage(webapp2.RequestHandler):
    def get(self):
        #get project_id from context
        context = verify_context(self.request.cookies.get('signed_request'))
        current_project_id = context['context']['environment']['current_project']
        project_info = ndb.Key(Project_info, current_project_id).get()

        if "code" in self.request.query_string:
            code = self.request.query_string.split("code=")[1].split("&")[0]
            #get credentials object
            clear_credentials = flow.step2_exchange(code)
            #pickle and then encrypt credentials object
            pickled_credentials = pickle.dumps(clear_credentials)
            credentials = obj.encrypt(pickled_credentials)
            project_info.credentials = credentials
            project_info.put()

            self.response.write(GENERIC_PAGE_TEMPLATE % ("<script>window.close()</script>"))
        else:
            self.response.write(GENERIC_PAGE_TEMPLATE % ("Uh oh, you aren't authenticated!"))



class SelectPage(webapp2.RequestHandler):
    def get(self):
        #get project_id from context
        context = verify_context(self.request.cookies.get('signed_request'))
        current_project_id = context['context']['environment']['current_project']

        #get clear credentials
        clear_credentials = ClearCredentials(current_project_id)

        http_auth = clear_credentials.authorize(httplib2.Http())
        analytics = build('analytics', 'v3', http=http_auth)

        #query the api
        segments = analytics.management().segments().list().execute()
        segment_list = ""
        for segment in segments['items']:
            value = json.dumps([segment['name'],segment['segmentId']])
            segment_list+= "<input type='radio' name='segment' value='%s'> %s (%s)<br>" % (value, segment['name'], segment['type'])
        self.response.write(SELECT_PAGE_TEMPLATE % (segment_list))


class CreatePage(webapp2.RequestHandler):
    def post(self):
        #get project_id from context
        context = verify_context(self.request.cookies.get('signed_request'))
        current_project_id = context['context']['environment']['current_project']
        session_token = context['context']['client']['access_token']

        if 'segment' in self.request.arguments():
            segment_obj = json.loads(self.request.get('segment'))
            segment_name_pre = re.sub('[^a-zA-Z0-9\-\_\s]', '-', segment_obj[0])
            segment_name = segment_name_pre.replace(' ','_')
            segment_id = segment_obj[1]

            #get clear_credentials for GA request
            clear_credentials = ClearCredentials(current_project_id)

            list_content = GetGAIds(current_project_id, segment_id, clear_credentials)
            #We should have all ids from results by now
            if len(list_content) > 0 and len(list_content) < 180000:
                data = {}
                data['list_content'] = ','.join(list_content)
                data['name'] = "GA_Segment__" + segment_name

                #check to see if there's already a list with this name
                url = "https://www.optimizelyapis.com/experiment/v1/projects/%s/targeting_lists/" % (current_project_id)
                response = rest_api_get(current_project_id, url, "bearer", session_token)
                optly_list_id = ""
                for item in response:
                    if item['name'] == data['name']:
                        optly_list_id = item['id']
                        break

                #optimizely post
                data['list_type'] = 1
                data['format'] = "csv"
                data['key_fields'] = "_ga"

                #Register the segment in ndb
                segment_info = Segment_info()
                segment_info.segment_name = segment_name
                segment_info.project_id = current_project_id
                segment_info.ga_id = segment_id

                if optly_list_id == "":
                    url = "https://www.optimizelyapis.com/experiment/v1/projects/%s/targeting_lists/" % (current_project_id)
                    response = rest_api_post(current_project_id, url, data, session_token)
                    segment_info.optly_id = response['id']
                    segment_info.key = ndb.Key(Segment_info, "%s:%s" % (current_project_id, response['id']))
                    segment_info.put()

                    self.response.write(CREATE_PAGE_TEMPLATE % ('<h1>Created an Optimizely Uploaded Audience with %s IDs!  Your list is named "%s".</h1>' % (len(list_content), data['name'])))
                else:
                    url = "https://www.optimizelyapis.com/experiment/v1/targeting_lists/%s/" %(optly_list_id)
                    response = rest_api_put(current_project_id, url, data, "bearer", session_token)
                    segment_info.optly_id = optly_list_id
                    segment_info.key = ndb.Key(Segment_info, "%s:%s" % (current_project_id, optly_list_id))
                    segment_info.put()

                    self.response.write(CREATE_PAGE_TEMPLATE % ('<h1>This segment had already been imported as "%s".  Updated with fresh data, your list now has %s IDs.</h1>' % (data['name'], len(list_content))))

            else:
                self.response.write(CREATE_PAGE_TEMPLATE % ('<h1>Uh oh!  Looks like your segment named "%s" has %s users!</h1><p>(We can only handle lists of less than 180,000 users)</p><a href="/select">Select another segment</a>' % (segment_name, len(list_content))))
        else:
            self.response.write(GENERIC_PAGE_TEMPLATE % ("Uh oh, you've skipped a step!"))


class SchedulePage(webapp2.RequestHandler):
    def get(self):
        #get project_id from context
        context = verify_context(self.request.cookies.get('signed_request'))
        current_project_id = context['context']['environment']['current_project']
        project_info = ndb.Key(Project_info, current_project_id).get()

        #check if project has an API Token
        if project_info.api_token == None:
            self.response.write(SCHEDULE_PAGE_TEMPLATE_1)

        else:
            #get a list of segments which have already been registered with Optly and check to see if they are enabled for automatic updating
            qry = Segment_info.query(Segment_info.project_id == project_info.project_id)
            segment_list = qry.fetch()

            enabled_segments = ""
            disabled_segments = ""
            #format segment_list for display
            for segment_info in segment_list:
                if segment_info.auto_update == True:
                    enabled_segments += "<input type='checkbox' name='segment_id' value='%s'>%s<br>" % (segment_info.optly_id, segment_info.segment_name)
                elif segment_info.auto_update == False:
                    disabled_segments += "<input type='checkbox' name='segment_id' value='%s'>%s<br>" % (segment_info.optly_id, segment_info.segment_name)

            if enabled_segments == "":
                enabled_form = '<div>No segments enabled</div>'
            else:
                enabled_form = "<form action='/update' method='post'>%s<input type='submit' value='Disable Selected Segments'></form>" % (enabled_segments)

            if disabled_segments == "":
                disabled_form = '<div>No segments disabled</div>'
            else:
                disabled_form = "<form action='/update' method='post'>%s<input type='submit' value='Enable Selected Segments'></form>" % (disabled_segments)

            clear_api_token = obj.decrypt(project_info.api_token)
            token_fragment = clear_api_token[len(clear_api_token)-6:]

            #calculate last run
            last_run = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(project_info.last_cron_end))

            self.response.write(SCHEDULE_PAGE_TEMPLATE_2 % (last_run, token_fragment, project_info.update_cadence_str, enabled_form, disabled_form))

class UpdatePage(webapp2.RequestHandler):
    def post(self):
        context = verify_context(self.request.cookies.get('signed_request'))
        current_project_id = context['context']['environment']['current_project']

        if 'segment_id' in self.request.arguments():
            segment_ids = self.request.get_all('segment_id')
            formatted_status = ""
            for optly_id in segment_ids:
                segment_info = ndb.Key(Segment_info, "%s:%s" % (current_project_id, optly_id)).get()
                if segment_info.auto_update == False:
                    segment_info.auto_update = True
                    formatted_status += '<p>Enabled auto-update for Segment "%s"</p>' % (segment_info.segment_name)
                elif segment_info.auto_update == True:
                    segment_info.auto_update = False
                    formatted_status += '<p>Disabled auto-update for Segment "%s"</p>' % (segment_info.segment_name)

                segment_info.put()
            self.response.write(UPDATE_PAGE_TEMPLATE % (formatted_status))
        else:
            self.response.write(GENERIC_PAGE_TEMPLATE % ("Uh oh, you've skipped a step!"))

class SettingsPage(webapp2.RequestHandler):
    def get(self):
        #get project_id from context
        context = verify_context(self.request.cookies.get('signed_request'))
        current_project_id = context['context']['environment']['current_project']
        project_info = ndb.Key(Project_info, current_project_id).get()

        #get clear credentials
        clear_credentials = ClearCredentials(current_project_id)

        http_auth = clear_credentials.authorize(httplib2.Http())
        analytics = build('analytics', 'v3', http=http_auth)

        #query the api for a list of views
        profiles = analytics.management().profiles().list(accountId='~all', webPropertyId='~all').execute()

        #construct the picklist of views
        view_list = ""
        for view in profiles['items']:
            if 'websiteUrl' in view:
                view_name = "%s - %s (ID: %s)" % (view['websiteUrl'], view['name'], view['id'])
            else:
                view_name = "%s - %s (ID: %s)" % ("no url", view['name'], view['id'])
            value = view['id']
            if project_info.view_id != None:
                if view['id'] in project_info.view_id:
                    view_list += "<option value='%s' selected>%s</option>" % (value, view_name)
                else:
                    view_list += "<option value='%s'>%s</option>" % (value, view_name)
            else:
                view_list += "<option value='%s'>%s</option>" % (value, view_name)

        #set helptext for interval and dimension_id
        if project_info.interval == None:
            interval_text = "<p>Number of days in the past to query: <input type='text' name='interval' required></p>"
        else:
            interval_text = "<p>Currently querying the past <b>%s days</b>.<br>Enter a new period? <input type='text' name='interval'></p>" % (project_info.interval.split('daysAgo')[0])

        if project_info.dimension_id == None:
            dimension_text = "<p>Index of dimension where _ga cookie value is stored: <input type='text' name='dimension_id' required></p>"
        else:
            dimension_text = "<p>Current index for dimension where _ga cookie value is stored: <b>%s</b>.<br>Set new Dimension? <input type='text' name='dimension_id'></p>" % (project_info.dimension_id.split('ga:dimension')[1])

        self.response.write(SETTINGS_PAGE_TEMPLATE % (view_list, interval_text, dimension_text))


class SettingsConfPage(webapp2.RequestHandler):
    def post(self):
        #get project_id from context
        context = verify_context(self.request.cookies.get('signed_request'))
        current_project_id = context['context']['environment']['current_project']

        arg_list = self.request.arguments()
        if len(arg_list) > 0:

            #get PROJECT object
            project_info = ndb.Key(Project_info, current_project_id).get()

            settings = ""
            for arg in arg_list:
                if "api_token" in arg:
                    api_token = self.request.get(arg)
                    if len(api_token) > 0:
                        encrypt_api_token = obj.encrypt(api_token)
                        project_info.api_token = encrypt_api_token
                        settings += '<p>API Token: %s</p>' %(api_token)
                elif "update_cadence" in arg:
                    cadence_str = self.request.get(arg)
                    try:
                        cadence_int = int(cadence_str)
                        unit = self.request.get("unit")
                        if unit == "hours":
                            project_info.update_cadence = cadence_int * 3600
                        if unit == "days":
                            project_info.update_cadence = cadence_int * 86400
                        project_info.update_cadence_str = cadence_str+" "+unit
                        settings += '<p>Update Cadence: Every %s %s</p>' % (cadence_str, unit)
                    except:
                        pass
                elif "view_id" in arg:
                    view_id = self.request.get(arg)
                    if len(view_id) > 0:
                        project_info.view_id = "ga:" + view_id
                        settings += '<p>GA View ID: %s</p>' %(view_id)
                elif "interval" in arg:
                    interval = self.request.get(arg)
                    try:
                        int(interval)
                        project_info.interval = interval + "daysAgo"
                        settings += '<p>GA Data Range: Last %s days</p>' %(interval)
                    except:
                        pass
                elif "dimension_id" in arg:
                    dimension_id = self.request.get(arg)
                    try:
                        int(dimension_id)
                        project_info.dimension_id = "ga:dimension" + dimension_id
                        settings += '<p>GA Cookie Dimension Index: %s</p>' %(dimension_id)
                    except:
                        pass

            project_info.put()

            html = "<h1>Settings Confirmation</h1>%s" % (settings)

            if '/schedule' in self.request.referer:
                html += "<p><a href='/schedule'>Back to Auto-update settings</a></p>"

            self.response.write(GENERIC_PAGE_TEMPLATE % (html))

        else:
            self.response.write(GENERIC_PAGE_TEMPLATE % ("Uh oh, you've skipped a step!"))

class CronPage(webapp2.RequestHandler):
    def get(self):
        #diagnostic report:
        html = ""

        #get all projects with api_token defined (if not, implies that user hasn't gone through auto-update config flow)
        qry = Project_info.query(Project_info.api_token != None)
        projects = qry.fetch()

        for project_info in projects:
            #set var to see if anything was updated in this project
            project_updated = False
            print "Now working on project", project_info.project_id
            #check for last update and proceed if it has been longer than the cadence value (which is number of seconds)
            if (int(time.time()) - project_info.update_cadence >= project_info.last_cron_end):
                print "passed time check"
                #get all segments where auto_update = True
                qry = Segment_info.query(Segment_info.auto_update == True, Segment_info.project_id == project_info.project_id)
                update_segments = qry.fetch()
                print "List of segments to check:", update_segments

                #get and decrypt GA credentials object
                clear_credentials = ClearCredentials(project_info.project_id)

                #get and decrypt optly api_token
                clear_api_token = obj.decrypt(project_info.api_token)

                #get list of uploaded audience ids from Optly for project
                url = "https://www.optimizelyapis.com/experiment/v1/projects/%s/targeting_lists/" % (project_info.project_id)
                response = rest_api_get(project_info.project_id, url, "standard", clear_api_token)
                optly_id_list = []
                for uploaded_list in response:
                    optly_id_list.append(uploaded_list['id'])

                for segment_info in update_segments:
                    print "Now checking segment with this info:", segment_info
                    #check and make sure the segment still exists in Optly project:
                    deleted = True
                    if segment_info.optly_id in optly_id_list:
                        deleted = False

                    #list has been deleted from Optly, so delete the segment from our app
                    if deleted == True:
                        segment_info.key.delete()
                    #segment is still in Optly project, so...
                    elif deleted == False:
                        print "now getting list_content"
                        #update list with fresh GA data
                        list_content = GetGAIds(project_info.project_id, segment_info.ga_id, clear_credentials)
                        #We should have all ids from results by now
                        if len(list_content) > 0 and len(list_content) < 180000:
                            print "list_content contains data"
                            data = {}

                            data['list_content'] = ','.join(list_content)
                            data['name'] = "GA_Segment__" + segment_info.segment_name
                            data['list_type'] = 1
                            data['format'] = "csv"
                            data['key_fields'] = "_ga"
                            url = "https://www.optimizelyapis.com/experiment/v1/targeting_lists/%s/" % (segment_info.optly_id)
                            response = rest_api_put(project_info.project_id, url, data, "standard", clear_api_token)
                            html += "NEXT UPDATE RESPONSE: %s" % (response)
                            project_updated = True

            #check to see if at least one segment was updated and then update last run time
            if project_updated == True:
                project_info.last_cron_end = int(time.time())
                project_info.put()

        if len(html) == 0:
            print "No lists updated"
        else:
            print html

class ResetPage(webapp2.RequestHandler):
    def get(self):
        #get project_id from context
        context = verify_context(self.request.cookies.get('signed_request'))
        current_project_id = context['context']['environment']['current_project']

        qry = Segment_info.query(Segment_info.project_id == current_project_id)
        segments = qry.fetch()
        for segment in segments:
            segment.key.delete()

        project_info = ndb.Key(Project_info, current_project_id).get()
        project_info.key.delete()

        self.response.write(GENERIC_PAGE_TEMPLATE % ("ok, reset everything"))

#-------------------------------------------------------------

#Instantiate the app and define our path mappings
app = webapp2.WSGIApplication([('/', MainPage),
    ('/oauth', OAuthPage),
    ('/create', CreatePage),
    ('/select', SelectPage),
    ('/schedule', SchedulePage),
    ('/update', UpdatePage),
    ('/cron', CronPage),
    ('/settings', SettingsPage),
    ('/settings_conf', SettingsConfPage),
    ('/reset', ResetPage)
    ],
    debug=True)
