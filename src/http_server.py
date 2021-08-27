# Our main wifi-connect application, which is based around an HTTP server.

import os, getopt, sys, json, atexit
import signal
import time
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs
from io import BytesIO
import argparse

# Local modules
import netman
import dnsmasq

# Defaults
ADDRESS = '192.168.42.1'
PORT = 80
UI_PATH = '../ui'

initial_connection_config_file = '/etc/initial_connection.json'

def get_initial_connection_config():
  if os.path.exists(initial_connection_config_file) and os.path.getsize(initial_connection_config_file) > 0:
    with open(initial_connection_config_file, 'r') as f:
      config_json = json.load(f)
      return config_json
  else:
    return None

def write_initial_connection_config(config_dict):
    with open(initial_connection_config_file, 'w') as f:
        json.dump(config_dict, f)
#------------------------------------------------------------------------------
# called at exit
def cleanup():
    print("Cleaning up prior to exit.")
    dnsmasq.stop()
    netman.stop_hotspot()
    dnsmasq.restart_dnsmasq_service()


#------------------------------------------------------------------------------
# A custom http server class in which we can set the default path it serves
# when it gets a GET request.
class MyHTTPServer(HTTPServer):
    def __init__(self, base_path, server_address, RequestHandlerClass):
        self.base_path = base_path
        HTTPServer.__init__(self, server_address, RequestHandlerClass)


#------------------------------------------------------------------------------
# A custom http request handler class factory.
# Handle the GET and POST requests from the UI form and JS.
# The class factory allows us to pass custom arguments to the handler.
def RequestHandlerClassFactory(address, ssids, rcode, hotspot_name="HOTSPOT", hotspot_password="", device_name=""):

    class MyHTTPReqHandler(SimpleHTTPRequestHandler):

        def __init__(self, *args, **kwargs):
            # We must set our custom class properties first, since __init__() of
            # our super class will call do_GET().
            self.address = address
            self.ssids = ssids
            self.rcode = rcode
            self.hotspot_name = hotspot_name
            self.hotspot_password = hotspot_password
            self.device_name = device_name
            super(MyHTTPReqHandler, self).__init__(*args, **kwargs)

        # See if this is a specific request, otherwise let the server handle it.
        def do_GET(self):

            print(f'do_GET {self.path}')

            # Handle the hotspot starting and a computer connecting to it,
            # we have to return a redirect to the gateway to get the 
            # captured portal to show up.
            if '/hotspot-detect.html' == self.path:
                self.send_response(301) # redirect
                new_path = f'http://{self.address}/'
                print(f'redirecting to {new_path}')
                self.send_header('Location', new_path)
                self.end_headers()

            if '/generate_204' == self.path:
                self.send_response(301) # redirect
                new_path = f'http://{self.address}/'
                print(f'redirecting to {new_path}')
                self.send_header('Location', new_path)
                self.end_headers()

            # Handle a REST API request to return the device registration code
            if '/regcode' == self.path:
                self.send_response(200)
                self.end_headers()
                response = BytesIO()
                response.write(self.rcode.encode('utf-8'))
                print(f'GET {self.path} returning: {response.getvalue()}')
                self.wfile.write(response.getvalue())
                return
            if '/device_name' == self.path:
                self.send_response(200)
                self.end_headers()
                response = BytesIO()
                response.write(self.device_name.encode('utf-8'))
                print(f'GET {self.path} returning: {response.getvalue()}')
                self.wfile.write(response.getvalue())
                return

            # Handle a REST API request to return the list of SSIDs
            if '/networks' == self.path:
                self.send_response(200)
                self.end_headers()
                response = BytesIO()
                ssids = self.ssids # passed in to the class factory
                """ map whatever we get from net man to our constants:
                Security:
                    NONE         
                    HIDDEN         
                    WEP         
                    WPA        
                    WPA2      
                    ENTERPRISE
                Required user input (from UI form):
                    NONE                   - No input requried.
                    HIDDEN, WEP, WPA, WPA2 - Need password.
                    ENTERPRISE             - Need username and password.
                """
                response.write(json.dumps(ssids).encode('utf-8'))
                print(f'GET {self.path} returning: {response.getvalue()}')
                self.wfile.write(response.getvalue())
                return

            # Not sure if this is just OSX hitting the captured portal,
            # but we need to exit if we get it.
            if '/bag' == self.path:
                sys.exit()

            # All other requests are handled by the server which vends files 
            # from the ui_path we were initialized with.
            super().do_GET()


        # test with: curl localhost:5000 -d "{'name':'value'}"
        def do_POST(self):
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            self.send_response(200)
            self.end_headers()
            response = BytesIO()
            fields = parse_qs(body.decode('utf-8'))
            print(f'POST received: {fields}, path:{self.path}')
            initial_config_params = {"device_name": fields['device_name'][0]}
            if fields['connection_type'][0]=="lte":
                # Stop the hotspot
                netman.stop_hotspot()
                initial_config_params["lte_only"] = True
                write_initial_connection_config(initial_config_params)
                success = True
            else:
                # Parse the form post
                FORM_SSID = 'ssid'
                FORM_HIDDEN_SSID = 'hidden-ssid'
                FORM_USERNAME = 'identity'
                FORM_PASSWORD = 'passphrase'

                if FORM_SSID not in fields:
                    print(f'Error: POST is missing {FORM_SSID} field.')
                    return

                ssid = fields[FORM_SSID][0]
                password = None
                username = None
                if FORM_HIDDEN_SSID in fields: 
                    ssid = fields[FORM_HIDDEN_SSID][0] # override with hidden name
                if FORM_USERNAME in fields: 
                    username = fields[FORM_USERNAME][0] 
                if FORM_PASSWORD in fields: 
                    password = fields[FORM_PASSWORD][0] 

                # Look up the ssid in the list we sent, to find out its security
                # type for the new connection we have to make
                conn_type = netman.CONN_TYPE_SEC_NONE # Open, no auth AP

                if FORM_HIDDEN_SSID in fields: 
                    conn_type = netman.CONN_TYPE_SEC_PASSWORD # Assumption...

                for s in self.ssids:
                    if FORM_SSID in s and ssid == s[FORM_SSID]:
                        if s['security'] == "ENTERPRISE":
                            conn_type = netman.CONN_TYPE_SEC_ENTERPRISE
                        elif s['security'] == "NONE":
                            conn_type = netman.CONN_TYPE_SEC_NONE 
                        else:
                            # all others need a password
                            conn_type = netman.CONN_TYPE_SEC_PASSWORD
                        break

                # Stop the hotspot
                netman.stop_hotspot()

                # Connect to the user's selected AP
                success = netman.connect_to_AP(conn_type=conn_type, conn_name=ssid, ssid=ssid, \
                        username=username, password=password)

                if success:
                    initial_config_params["lte_only"] = False
                    write_initial_connection_config(initial_config_params)
                    response.write(b'OK\n')
                else:
                    response.write(b'ERROR\n')
                self.wfile.write(response.getvalue())

            # Handle success or failure of the new connection
            if success:
                print(f'Connected!  Exiting app.')
                sys.exit()
            else:
                print(f'Connection failed, restarting the hotspot.')

                # Update the list of SSIDs since we are not connected
                self.ssids = netman.get_list_of_access_points()

                # Start the hotspot again
                netman.start_hotspot(self.hotspot_name, self.hotspot_password) 

    return  MyHTTPReqHandler # the class our factory just created.


def exit_on_timeout(timeout_seconds):
    time_start = time.time()
    while time.time() - time_start < timeout_seconds:
        time.sleep(0.4)
    print("Timeout Expired, exiting...")
    os.kill(os.getpid(), signal.SIGINT)

#------------------------------------------------------------------------------
# Create the hotspot, start dnsmasq, start the HTTP server.
# def main(address, port, ui_path, rcode, delete_connections):
def main(args):
    address = args.address
    port = args.port
    ui_path = args.ui_dir
    rcode = args.registration_code
    delete_connections = args.delete_connections_first
    timeout = args.timeout
    hotspot_name = args.hotspot_name
    hotspot_password = args.hotspot_password
    device_name = args.device_name

    initial_connection_config = get_initial_connection_config()
    if initial_connection_config is not None and initial_connection_config.get("lte_only", False):
        print(f"Connection has already been configured to LTE only and device config has not yet been updated. Exiting")
        sys.exit()
    # Start a thread to keep track of time and exit when timeout has passed
    t=threading.Thread(target=exit_on_timeout, args=[timeout])
    t.setDaemon(True)
    t.start()
    # See if caller wants to delete all existing connections first
    if delete_connections:
        netman.delete_all_wifi_connections()

    # Check if we are already connected, if so we are done.
    # if netman.have_active_internet_connection():
    #     print('Already connected to the internet, nothing to do, exiting.')
    #     sys.exit()

    # Get list of available AP from net man.  
    # Must do this AFTER deleting any existing connections (above),
    # and BEFORE starting our hotspot (or the hotspot will be the only thing
    # in the list).
    ssids = netman.get_list_of_access_points()

    # Start the hotspot
    if not netman.start_hotspot(hotspot_name, hotspot_password):
        print('Error starting hotspot, exiting.')
        sys.exit(1)

    # Start dnsmasq (to advertise us as a router so captured portal pops up
    # on the users machine to vend our UI in our http server)
    dnsmasq.start()

    # Find the ui directory which is up one from where this file is located.
    web_dir = os.path.join(os.path.dirname(__file__), ui_path)
    print(f'HTTP serving directory: {web_dir} on {address}:{port}')

    # Change to this directory so the HTTPServer returns the index.html in it 
    # by default when it gets a GET.
    os.chdir(web_dir)

    # Host:Port our HTTP server listens on
    server_address = (address, port)

    # Custom request handler class (so we can pass in our own args)
    MyRequestHandlerClass = RequestHandlerClassFactory(address, ssids, rcode, hotspot_name, device_name=device_name)

    # Start an HTTP server to serve the content in the ui dir and handle the 
    # POST request in the handler class.
    print(f'Waiting for a connection to our hotspot {hotspot_name} ...')
    httpd = MyHTTPServer(web_dir, server_address, MyRequestHandlerClass)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        dnsmasq.stop()
        netman.stop_hotspot()
        httpd.server_close()


#------------------------------------------------------------------------------
# Util to convert a string to an int, or provide a default.
def string_to_int(s, default):
    try:
        return int(s)
    except ValueError:
        return default


#------------------------------------------------------------------------------
# Entry point and command line argument processing.
if __name__ == "__main__":
    atexit.register(cleanup)

    address = ADDRESS
    port = PORT
    ui_path = UI_PATH
    delete_connections = False
    rcode = ''

    usage = ''\
f'Command line args: \n'\
f'  -a <HTTP server address>     Default: {address} \n'\
f'  -p <HTTP server port>        Default: {port} \n'\
f'  -u <UI directory to serve>   Default: "{ui_path}" \n'\
f'  -d Delete Connections First  Default: {delete_connections} \n'\
f'  -r Device Registration Code  Default: "" \n'\
f'  -h Show help.\n'

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-a', '--address',
                        help='HTTP server address', required=False, default=address)
    parser.add_argument('-p', '--port',
                        help='HTTP server port', required=False, default=port, type=int)
    parser.add_argument('-u', '--ui_dir', help='UI directory to serve',
                        required=False, default=ui_path)
    parser.add_argument('-d', '--delete',
                        help='Delete Connections First', default=False, required=False, dest="delete_connections_first", action='store_true')
    parser.add_argument('-r', '--registration_code',
                        help='Device Registration Code', required=False, default="")
    parser.add_argument('-t', '--timeout',
                        help='Timeout seconds', required=False, default=0, type=int)
    parser.add_argument('-s', '--hotspot_name',
                        help='HotSpot name to create', required=False, default="CurbSensor")
    parser.add_argument('-e', '--hotspot_password',
                        help='Password to use for the HotSpot', required=False, default="")
    parser.add_argument('-n', '--device_name',
                        help='Device name to prefill the field with', required=False, default="")
    
    args = parser.parse_args()

    # print(args)
    main(args)


