import os
import check_ext
import json

path = "D:/ProgramD/MyCode/CS5331 Project/attemp1/test_extensions"

def get_filelist(dir):
    Filelist = []
    for home, dirs, files in os.walk(dir):
        for filename in files:
            Filelist.append(os.path.join(home,filename))
    return Filelist

Filelist = get_filelist(path)

cnt = 0

for file in Filelist:
    file_path = file.replace('\\', '/')
    report = check_ext.analyzelocalfirefoxextension(file)
    print('report:',report)
    file_name = os.path.basename(file_path)
    report_file_name = file_name+".json"
    report_file_path = "D:/ProgramD/MyCode/CS5331 Project/attemp1/reports/"+report_file_name

    with open(report_file_path, "w") as f:
        json.dump(report, f)
