import os
import sys
import configparser
import json
import logging
import traceback
import zipfile
import shutil
# import helper as helper
import analyze as analysis

extract_path = 'D:/ProgramD/MyCode/CS5331 Project/attemp1/extract'

def analyzelocalfirefoxextension(path):
    if os.path.isfile(path) and path.endswith('.xpi'):
        #  checks whether a given path exists and is a file
        extract_directory = extract_path + '/temp_extract_directory'
        try:
            zip_contents = zipfile.ZipFile(path,'r')
            zip_contents.extractall(extract_directory)
            zip_contents.close()
        except Exception as e:
            logging.error(traceback.format_exc())
            return False
        analysis_report = analysis.analyze(extract_directory,'Local Firefox Extension')
        # print('analysis_status:',analysis_report)

        if 'error:' in analysis_report:
            print('Something went wrong while analysis')
        else:
            print('Scanning complete')
        
        shutil.rmtree(extract_directory)
        return analysis_report
    
    else:
        print('Invalid local firefox extension path:'+path)
        
# analyzelocalfirefoxextension('D:/ProgramD/MyCode/CS5331 Project/attemp1/1_click_email_url-1.0.4.xpi')
