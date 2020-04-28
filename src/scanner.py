import queue
import multiprocessing
from time import sleep
import json
import hashlib
import os
import sys
import argparse
import requests
import configparser
import yara

class Scanner():
    
    def __init__(self, root_dir, binaries_only):
        
        config = configparser.ConfigParser()
        config.read('scanner_config.ini')
        self.api_key = config['virustotal.com']['API_KEY']
        self.throttle_sleep = int(config['virustotal.com']['VIRUS_TOTAL_THROTTLE_SLEEP'])
        self.hash_dict_file = config['default']['hash_dict_file']
        self.yara_file = config['default']['yara_file']
        
        self.root_dir = root_dir
        self.binaries_only = binaries_only
        
        self.queue = multiprocessing.Queue()
        
        self.yara_rules = yara.compile(self.yara_file)
        
    # compute the sha256 hash of a file.  Takes the 
    # complete filepath as an arument.  Reads the file 
    # in blocks to avoid issues with reading huge files in
    # one go.
    def ComputeSha256(self, filename, block_size=65536):
        sha256 = hashlib.sha256()
        
        with open(filename, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                sha256.update(block)
        
        return sha256.hexdigest()
    
    # Run YARA rules against a file.  Read the file in blocks to 
    # avoid issues with huge files.
    def MatchAgainstYARARules(self, filename, block_size=65536):
        matching_rules = []
        
        with open(filename, 'rb') as f:
            old_block = bytes()
            
            for block in iter(lambda: f.read(block_size), b''):
                combined_blocks = old_block + block
                old_block = block
                matches = self.yara_rules.match(data=combined_blocks)
                  
                if(len(matches) > 0):
                    print("Matched with following YARA rule(s):")
                    for i in matches:
                        print(i)
                        matching_rules.append(str(i))
                        
        return matching_rules
    
    # Print out the contents of the hash dictionary
    def DisplayDictionarySummary(self, hash_dict):
        keys = hash_dict.keys()
        
        safe_hashes = []
        flagged_hashes = []
        unknown_hashes = []
        yara_hashes = []
        
        for key in keys:
            if (hash_dict[key][0] == 0):
                unknown_hashes.append(key)
            else:
                # if at least one antivirus flagged it,
                # mark is as flagged
                if (hash_dict[key][3] > 1):
                    flagged_hashes.append(key)
                else:
                    safe_hashes.append(key)
                  
            # if it hit any yara rules
            if (len(hash_dict[key][4]) > 0):
                yara_hashes.append(key)
             
        print("\nResults Summary\n")

        print("================VirusTotal Results================")
        print("VirusTotal: Safe files:")
        for f in safe_hashes:
            print("%s %s" % (f, hash_dict[f][1]))
            
        print("\nVirusTotal: Flagged Files:")
        for f in flagged_hashes:
            print("%s %s" % (f, hash_dict[f][1]))
            
        print("\nVirusTotal: Unknown Files:")
        for f in unknown_hashes:
            print("%s %s" % (f, hash_dict[f][1]))   
            
        print("\n===================YARA Results===================")
        print("Yara Matches:")
        for f in yara_hashes:
            print("%s %s" % (f, hash_dict[f][1]))
            
            rules = hash_dict[f][4]
            
            print("rules: ", end='')
            for i in rules:
                print("%s " % i, end = '')
            
            print("\n\n", end='')

    def OpenHashDict(self):
        hashes_file = None
        
        try:
            hashes_file = open(self.hash_dict_file, 'r')
            
            try:
                hash_dict = json.loads(hashes_file.read())
            except Exception as e:
                print('Error loading json from hash_dict')
                print(e)
                hash_dict = {}
            
            hashes_file.close()
            
        except Exception as e:
            print('Error opening hash_dict file')
            print(e)
            hash_dict = {}
        
        return hash_dict
    
    def WriteHashDict(self, hash_dict):
        try:
            f = open(self.hash_dict_file,'w')
            
            try:
                json.dump(hash_dict, f)
            except Exception as e:
                print('Error dumping json')
                print(e)
                
            f.close()
        except Exception as e:
           print('Error opening file to write hash_dict')
           print(e)
            
    def WriteDictToCsv(self, hash_dict, csv_file):
        try:
            f = open('test.csv', 'w')
            f.write('filename,VT_found,VT_num_scans,VT_num_hits,YARA_matches,file_hash\n')
            for key in hash_dict.keys():
                f.write("%s,%s,%s,%s,%s, %s\n"%(hash_dict[key][1], hash_dict[key][0], hash_dict[key][2], hash_dict[key][3], ';'.join(hash_dict[key][4]), key))
            f.close()
        
        except Exception as e:
            print('Error opening CSV file for writing')
            print(e)
            return
        
    # Send a request to Virustotal
    # It is possible to send more than 1 hash at a time, however,
    # VirusTotal.com considers each database lookup a request
    # so this doesn't allow you to get around the rate limiting.
    def GetFileReport(self, filehash):
        params = {'apikey': self.api_key, 'resource': filehash}
        
        try:
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, timeout=None)
        except requests.RequestException as e:
            print('Error with VirusTotal request')
            print(e)
            return None
       
        if(response.status_code == 204):
            print('Error: VirusTotal Rate Limit exceeded')
            return None
        elif(response.status_code == 403):
            print('Error: VirusTotal returned HTTP Error 403 Forbidden')
            return None
        else:
            return response.json()
        
    # Get hashes from the directory traversal loop and
    # determines whether or not to look them up on
    # VirusTotal
    def RequestHandler(self, queue):
        request = ("", "")
        
        hash_dict = self.OpenHashDict()
        
        # run the requests loop until we get the signal to stop
        while(True):
            request = queue.get()
        
            filename = request[0]
            hashval = request[1]
            
            matches = []
            
            # this is the signal to stop
            if(filename == "Done"):
                break
            
            # if the hash isn't in the dictionary or it is but is categorized as unknown,
            # search for it in VirusTotal.
            if((hash_dict.get(hashval) == None) or (hash_dict.get(hashval)[0] == 0)):
                
                response = self.GetFileReport(hashval)
                
                if(response != None):
                    # The response code indicates whether or
                    # not the hash is in VirusTotal
                    response_code = response['response_code']
                    print("Results:")
                    print("File Path: %s" % filename)
                    print("SHA256 Hash Value: %s" % hashval)
                    
                    # The hash is in VirusTotal
                    if(response_code == 1):
                        # get the total number of malicious flags and
                        # the total number of scans run
                        num_total = response['total']
                        num_positives = response['positives']
                        
                        print("VirusTotal: Found")
                        
                        print("Total Scans: %d" % num_total)
                        print("Total positives: %d" % num_positives)
                        
                        hash_dict[hashval] = (response_code, filename, num_total, num_positives, matches)

                    # The hash isn't in VirusTotal
                    # Use YARA to look at the file and see if there are any matches
                    else:
                        print("VirusTotal: Not Found")
                        
                        matches = self.MatchAgainstYARARules(filename)
                        
                        hash_dict[hashval] = (response_code, filename, 0, 0, matches)
                    
                    print('\n', end='')
                
                # the VirusTotal Public API allows for up to 4 requests
                # per minute so throttling is required.
                sleep(self.throttle_sleep)
                
        self.WriteHashDict(hash_dict)
        
    # Starts the scan.  Creates a separate process to make requests to 
    # VirusTotal and uses a FIFO Queue to get that data to the process making the
    # requests.  
    def RunScan(self):
        
        p = multiprocessing.Process(
            target=self.RequestHandler,
            args=(self.queue,))
            
        p.start()
        
        for root, directories, filenames in os.walk(self.root_dir):
            for filename in filenames: 
        
                complete_path = os.path.join(root, filename)
                
                # If we only want to search for binaries, then the file
                # command is used to determine the filetype.  If it is an ELF,
                # it is hashed and the hash is sent to virus total.
                if(self.binaries_only):
                    file_type = os.popen("file %s" % complete_path).read()
            
                    if "ELF" in file_type:
                        filehash = self.ComputeSha256(complete_path)
                        self.queue.put((complete_path, filehash))
                else:
                    filehash = self.ComputeSha256(complete_path)
                    self.queue.put((complete_path, filehash))
                    
        self.queue.put(("Done", "Done"))
        
        print("Finished Directory Traversal. Please wait for VirusTotal requests to finish.\n")
        
        self.queue.close()
        self.queue.join_thread()
        p.join()
        
        print("Directory Traversal and VirusTotal Requests Complete")

        self.DisplayDictionarySummary(self.OpenHashDict())

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Recursively walk through a user specified directory and upload hashes of the files present to Virus Total.  The directory traversal loop and the VirusTotal requests loop run in parallel.  Due to restrictions on the public API key, no more than 4 requests per minute are allowed.  For configuration such as the API Key, hash dictionary location, and rate limiting see the scanner_config.ini file.')
    
    parser.add_argument('top_dir', metavar='<directory>', nargs='?', type=str, help='Top level of the directory tree you want to scan')
    
    parser.add_argument('--binaries_only', dest='binaries_only', action='store_true', help='Search for ELF binaries only.')
    
    parser.add_argument('--reset_dictionary', dest='reset_dict', action='store_true', help='Empties the hash dictionary, does not run any searches.  Leaves an empty dictionary in the file.')
    
    parser.add_argument('--results_summary', dest='summary', action='store_true', help='View results summary.  Does not run any searches')
    
    parser.add_argument('--results_to_csv', dest='to_csv', metavar='<csv_file>', type=str, help='Write out results to a csv file.  Does not run any searches')
   
    parser.set_defaults(binaries_only=False, reset_dict=False, summary=False, to_csv='')
    
    args = parser.parse_args()
        
    scanner = Scanner(args.top_dir, args.binaries_only)
    
    run_scan = True
    
    if(args.reset_dict):
        blank_dict = {}
        scanner.WriteHashDict(blank_dict)
        run_scan = False
        
    if(args.summary):
        hash_dict = scanner.OpenHashDict()
        scanner.DisplayDictionarySummary(hash_dict) 
        run_scan = False
        
    if(args.to_csv != ''):
        hash_dict = scanner.OpenHashDict()
        scanner.WriteDictToCsv(hash_dict, args.to_csv)
        run_scan = False
        
    if(run_scan):
        print('Starting Directory Traversal\n')   
        scanner.RunScan()
