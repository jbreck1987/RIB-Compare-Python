#Class for CSR1000V Objects for use
#with connecting to the built-in API

import requests
import json
import time
import urllib3

class cls_csr1kv:
    base_url = '/api/v1/'
    auth_url = 'auth/token-services'
    get_routes_url = 'routing-svc/routing-table'
    
    def __init__(self, address, hostname, port=None):
        self.address = address
        self.port = port
        self.hostname = hostname
        
    def __str__(self):
        return '{0}, {1}'.format(self.hostname, self.address)
    
    def getAuthToken(self, username, password):
        # Used to initiate a connection to the API of a node. It then returns
        # the authentication token for use in future requests of the session
        # via the "X-Auth-Token header for session authentication.
        # Accepts the node IP address, the baseUrl of the node's class,
        # and the authUrl of the node's class. The separate values
        # are concatenated together to create the entire request_url.
        # This helps keep the method API agnostic.
        # Construct the full token request URL from all sub-URLs passed
        # into the method
        
        if self.port == None:
            request_url = str('https://' + self.address
                                     + cls_csr1kv.base_url
                                     + cls_csr1kv.auth_url)
        else:
            request_url = str('https://' + self.address + ":"
                                     + self.port
                                     + cls_csr1kv.base_url
                                     + cls_csr1kv.auth_url)           
                                     
        print("\nConnecting to {}...\n\n".format(self.address))
        time.sleep(1)
        
        # Attempt to connect to the node using the full request URL and
        # print out the associated error message if connection fails.
        try:
            request_data = requests.post(request_url, verify=False,
                                    auth=(username, password)).json()
                                    
            print("Connected to {}".format(self.address))
            print("Getting token...\n\n")
            time.sleep(1)
            
        except:
            print("Had issues connecting to {}".format(self.address))
            print("Verify connectivity and auth")
            raise SystemExit
            
        else:
            # Return the value stored in the 'token-id'
            # index as the authentication token to be used
            # for the session
            return request_data['token-id']
         
    def getRoutes(self, authToken):
        headers = {'X-auth-token': authToken}
        
        if self.port == None:
            request_url = str('https://' + self.address
                                     + cls_csr1kv.base_url
                                     + cls_csr1kv.get_routes_url)
        else:
            request_url = str('https://' + self.address + ":"
                                     + self.port
                                     + cls_csr1kv.base_url
                                     + cls_csr1kv.get_routes_url)
                                     
        try:
            routes = requests.get(request_url, headers=headers,
                               verify=False).json()
        except:
            print("Had issues connecting to {}".format(self.address))
            print("Verify connectivity and auth")
            raise SystemExit
        else:            
            return routes
        
        
        
def main():
    # Used to disable security warnings due to
    # this programs use of self-signed certs
    urllib3.disable_warnings()
    
    # Instantiate CSR objects using the
    # cls_csr1kv Class
    csr1 = cls_csr1kv('198.51.100.41', 'R1')
    csr2 = cls_csr1kv('198.51.100.22', 'R2', '55443')
    
    # Connect to CSRs and authenticate (using Basic Auth)
    # to receive an auth token that will be used to authenticate
    # future requests
    csr1_token = csr1.getAuthToken('rest', 'api')
    csr2_token = csr2.getAuthToken('rest', 'api')
    
    # Once auth tokens have been granted and stored,
    # reach out to the CSRs again and pull their entire
    # routing table, in JSON format
    csr1_json = csr1.getRoutes(csr1_token)
    csr2_json = csr2.getRoutes(csr2_token)
    
    # Pass JSON to function that parses the data and
    # returns either the routes that are not in both tables or
    # returns an empty set if the RIBs match
    diff_routes = destNetsOnly(csr1_json, csr2_json)
    
    # Based on data returned from RIB comparison function(s),
    # output information to standard output
    if len(diff_routes) == 0:
        print("Destination networks are the same!")
    else:
        print("Check the following routes: ")
        print("{}".format(diff_routes))

def destNetsOnly(csr1_json, csr2_json):
    csr1_routes = set()
    for route in csr1_json['items']:
        csr1_routes.add(route['destination-network'])

    csr2_routes = set()
    for route in csr2_json['items']:
        csr2_routes.add(route['destination-network'])
        
    return csr1_routes.symmetric_difference(csr2_routes)
    

    
# def destNetsandNxHop(JSON_object)
# def destNetsandProto(JSON_object)
    
if __name__ == '__main__':
    main()