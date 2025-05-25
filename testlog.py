import csv
from datetime import datetime

def log_report(url, result):
    with open('phishing_reports.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), url, result])

log_report("http://test.com", "Safe")
