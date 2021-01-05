# Decoders API, Entravision, Author Marc Medina
# Python 3.8, McAllen Texas 78501, mmedina@entravision.com

import os
import numpy
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from pythonping import ping
import smtplib
import pandas as pd
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

html = message_html = """\
        <html>
        <body>
        <p>Hi,<br>
        Bitcentral Needs Your Attention</p>
        <p><a href="https://10.116.16.54/BitcentralWebMonitoring">Bitcentral Web Monitoring Website</a></p>
        <p> Feel free to <strong>email TOC</strong> at toc@entravision.com for help.</p>
        </body>
        </html>
        """

nevion_control_ips = [
    '172.16.11.235',
    '172.17.226.102',
    '172.18.6.110',
    '172.18.6.111',
    '172.19.6.180',
    '172.23.6.160',
    '172.24.6.62',
    '172.31.18.2',
    '172.31.23.4',
    '192.168.117.27',
    '192.168.128.34',
    '192.168.13.30',
    '192.168.25.205',
    '192.168.37.40',
    '192.168.62.100',
    '192.168.63.100',
    '192.168.64.100',
    '192.168.65.100',
    '192.168.66.100',
    '192.168.67.100',
    '192.168.68.100',
    '192.168.70.100',
    '192.168.73.100',
    '192.168.75.100'
]
alarm_log_head = 'On time,Off time,Sequence#,Severity#,Severity,Type,Alarm ID,Text,Source,Subid1,Subid2,Subid3,Details'
ini_path = 'D:/ERICA Data/Data/Decoders/Nevion TVG425 Alarms/'
critical_ini_path = 'D:/ERICA Data/Data/Decoders/Nevion TVG425 Alarms/Critical Alarms/'


def decoder_name(control_ip):
    try:
        method = 'http://'
        txp_call = '/txp_get?path=/dev/product_info|_select:devname'
        req = requests.get(method + control_ip + txp_call)
        soup = BeautifulSoup(req.content, 'lxml')
        x = soup.find('product_info')
        name = x.get('devname')
        return name
    except TimeoutError as e:
        print(e)
        pass


def decoder_date_and_time():
    today = datetime.now().strftime('%y%m%d')  # 201228
    return today


def decoder_date_and_time_year_first():
    today_2020_first = datetime.now().strftime('%Y-%m-%d')  # 2020-12-28
    return today_2020_first


def decoder_nevion_ping_robot():
    try:
        with open('nevion ping logs.csv', 'w')as ping_log:
            ping_log.write(str(decoder_date_and_time()) + '\n')
            r = []
            for control_ip in nevion_control_ips:
                print(ping(control_ip, count=4, verbose=True))
                print('Nevion Allocated to: ' + decoder_name(control_ip))
                x = ping(control_ip)
                print(x)
                ping_log.write(str(ping(control_ip, count=1, verbose=True)))
                h = str(ping(control_ip))
                r.append(h)
                pings = r

                return pings
    except TimeoutError as error:
        print(error)
        pass


def decoder_email_alert_notification(sender_email, receiver_email, subject, email_message_html):
    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = sender_email
        message["To"] = receiver_email
        # write the plain text part
        message_text = """
        ERICA - Automation Systems - Alert! (Test)
        """
        # write the HTML part
        # message_html = """\
        # <html>
        #   <body>
        #     <p>Hi,<br>
        #        Bitcentral Needs Your Attention</p>
        #     <p><a href="https://10.116.16.54/BitcentralWebMonitoring">Bitcentral Web Monitoring Website</a></p>
        #     <p> Feel free to <strong>email TOC</strong> at toc@entravision.com for help.</p>
        #   </body>
        # </html>
        # """
        # convert both parts to MIMEText objects and add them to the MIMEMultipart message
        message_text = MIMEText(message_text, "plain")
        email_message_html = MIMEText(email_message_html, "html")
        message.attach(message_text)
        message.attach(email_message_html)
        # send your email
        with smtplib.SMTP("172.16.5.9", 25) as server:
            server.sendmail(sender_email, receiver_email, message.as_string())
        print('Sent')
    except TimeoutError as error:
        print(error)
    return print('Sent')


def decoder_lock_status(control_ip):
    try:
        method = 'http://'
        txp_call = '/txp_get?path=/ports/ip_input|select=*/iprx/buff|_select:locked'
        req = requests.get(method + control_ip + txp_call)
        soup = BeautifulSoup(req.content, 'lxml')
        x = soup.find('buff')
        locked_state = x.get('locked')
        return locked_state
    except TimeoutError as e:
        print(e)
        pass


def decoder_actual_latency(control_ip):
    try:
        method = 'http://'
        txp_call = '/txp_get?path=/ports/ip_input|select=*/iprx/buff|_select:act_latency'
        req = requests.get(method + control_ip + txp_call)
        soup = BeautifulSoup(req.content, 'lxml')
        x = soup.find('buff')
        a_latency = x.get('act_latency')
        act_latency = a_latency
        return act_latency
    except TimeoutError as e:
        print(e)
        pass


def decoder_last_10_alarms_log(control_ip):
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=10'
        req = requests.get(method + control_ip + txp_call)
        print(req.text)
        data = req.text
        return data
    except TimeoutError as e:
        print(e)
        pass


def decoder_last_20_alarms(control_ip):
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=20'
        req = requests.get(method + control_ip + txp_call)
        print(req.text)
        data = req.text
        return data
    except TimeoutError as e:
        print(e)
        pass


def decoder_last_100_alarms(control_ip):
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=100'
        req = requests.get(method + control_ip + txp_call)
        print(req.text)
        data = req.text
        return data
    except TimeoutError as e:
        print(e)
        pass


def decoder_all_alarms(control_ip):
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit='
        req = requests.get(method + control_ip + txp_call)
        print(req.text)
        data = req.text
        return data
    except TimeoutError as e:
        print(e)
        pass


def decoder_generate_all_alarms_individual_csv_file(control_ip, decoder_name_call_letters):
    date = str(decoder_date_and_time())
    print(decoder_name_call_letters)
    with open(ini_path + str(decoder_name_call_letters) + '_Nevion_Alarm_log_' + date + '.csv',
              'w') as log:
        try:
            method = 'http://'
            txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=200'
            req = requests.get(method + control_ip + txp_call)
            log.write(req.text)
            log.close()
            print(req.text)
            data = req.text
            return data
        except TimeoutError as e:
            print(e)
            pass


def decoder_nevion_alarms_csv(control_ip):
    with open(ini_path + decoder_name(control_ip) + '.csv', 'w') as f:
        f.write(alarm_log_head)
        for control_ip in nevion_control_ips:
            f.write(decoder_name(control_ip) + '\n')
            f.write(decoder_date_and_time() + '\n')
            print(decoder_name(control_ip) + '\n')
            f.write(decoder_last_100_alarms(control_ip) + '\n')
            print(decoder_last_100_alarms(control_ip) + '\n')
        return f.close()


def decoder_get_name_and_lock_status():
    with open('Nevion Lock Status.csv', 'w')as f:
        try:
            for control_ip in nevion_control_ips:
                name = decoder_name(control_ip)
                locked = decoder_lock_status(control_ip)
                today = decoder_date_and_time()
                f.write('Call_Letter_Allocation,IP Transport Stream Lock Status,Today\n')
                print(name, locked, today, control_ip)
                f.write(name + ',' + locked + ',' + today + ',' + control_ip + '\n')
            for control_ip in nevion_control_ips:
                if locked == 'false':
                    print(
                        '++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n')
                    print('Warning!! The Following Nevion TVG425 IP-STLs are reporting a lock status of FALSE: \n')
                    print(name)
                    print(locked)
                    print(today)
                    return print(control_ip)
        except TimeoutError as error:
            print(error)

        return f.close(),


def decoder_nevion_alarms_stdout():
    with open('nevion_alarms_103120.csv', 'w') as f:
        for control_ip in nevion_control_ips:
            f.write(alarm_log_head)
            f.write(decoder_name(control_ip) + '\n')
            f.write('Date of Report: ' + decoder_date_and_time() + '\n')
            print('Nevion Call Sign Allocation: ' + decoder_name(control_ip) + '\n')
            f.write(decoder_last_10_alarms_log(control_ip) + '\n')
            f.write(':Latest 100 Alarms: ')
            print(decoder_last_100_alarms(control_ip) + '\n')
            f.write(decoder_last_100_alarms(control_ip) + '\n')
            print('Nevion IP TS Locked? ' + decoder_lock_status(control_ip) + '\n')
            f.write(decoder_lock_status(control_ip) + '\n')
        return f.close()


def decoder_analyze_nevions_critical_alarms_today():
    for control_ip in nevion_control_ips:
        # Timestamp format example 2020-12-27 02:19:13
        decoder_date = datetime.now().strftime('%Y-%m-%d')  # 2020-12-28

        alarm_logs_dir = os.listdir(ini_path)
        for index, row in alarm_logs_dir.inter:
            print(row, decoder_name(control_ip), str(control_ipntrol_ip))
        exit()







    # try:
    #     nevion_name = decoder_name(control_ip)
    #     method = 'http://'
    #     txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=20'
    #     req = requests.get(method + control_ip + txp_call)
    #     print(req.text)
    #     data = req.text
    #     alarm_log_data = pd.read_csv(data, delimiter=',', header=0)
    #
    #     x.write('On time,Off Time,Severity,Source,Text' + '\n')
    #     for index, row in log_data.iterrows():
    #         if row['Severity'] == 'Critical':
    #             x.write('On time: ' + str(row['On time']) + ',' + 'Off Time: ' + str(
    #                 row['Off time']) + ',' + 'Severity: ' + str(row['Severity']) + ',' + 'Source: ' + str(
    #                 row['Source']) + ',' + 'Text: ' + str(row['Text']) + '\n')




decoder_analyze_nevions_critical_alarms_today()

def decoder_analyze_nevion_timestamp(control_ip):

        for index, row in log_data.iterrows():
            if row['Severity'] == 'Critical':
                x.write('On time: ' + str(row['On time']) + ',' + 'Off Time: ' + str(
                    row['Off time']) + ',' + 'Severity: ' + str(row['Severity']) + ',' + 'Source: ' + str(
                    row['Source']) + ',' + 'Text: ' + str(row['Text']) + '\n')


def decoders_analyze_with_pandas():
    for control_ip in nevion_control_ips:
        decoder_analyze_nevions_critical_alarms_today(control_ip)
    return


def decoders_analyze_alarm_events(control_ip, level):
    log_dir = os.listdir(ini_path)
    nevion_name = decoder_name(control_ip)
    for log in log_dir:
        with pd.read_csv(ini_path + log, header=0, delimiter=',') as alarm_log:
            with open('Critical ' + nevion_name + str(decoder_date_and_time()) + '.csv') as critical_log:
                critical_log.write('On time,Off Time,Severity,Source,Text' + '\n')
                for index, row in alarm_log.iterrows():
                    if row['Severity'] == 'Critical' and row:
                        critical_log.write('On time: ' + str(row['On time']) + ',' + 'Off Time: ' + str(
                            row['Off time']) + ',' + 'Severity: ' + str(row['Severity']) + ',' + 'Source: ' + str(
                            row['Source']) + ',' + 'Text: ' + str(row['Text']))
                    if row['Severity'] == 'Critical':
                        print('On time: ' + row['On time'] + ',',
                              'Off Time: ' + row['Off time'] + ',' + 'Source: ' + str(
                                  row['Source'] + 'Text: ' + str(row['Text'])))
        # with open( ini_path + '/' + 'Nevion_Critical_Alarms__' + str(decoder_date_and_time()) + '_' + nevion_name +
        # '.csv', 'w') as critical_log_today: critical_log_today.write('On time: ' + str(row['On time']) + ',
        # ' + 'Off Time: ' + str(row['Off time']) + ',' + 'Severity: ' + str(row['Severity']) + ',' + 'Source: ' +
        # str(row['Source']) + ',' + 'Text: ' + str(row['Text'] + '\n'))

    critical_log.close()
    # critical_log_today.close()


def decoder_get_all_alarm_logs():
    for control_ip in nevion_control_ips:
        decoder_name_call_letters = decoder_name(control_ip)
        decoder_generate_all_alarms_individual_csv_file(control_ip, decoder_name_call_letters)
    for control_ip in nevion_control_ips:
        decoder_analyze_nevions_critical_alarms_today(control_ip)
    for control_ip in nevion_control_ips:
        print(decoder_name(control_ip), decoder_lock_status(control_ip), decoder_last_10_alarms_log(control_ip))


decoder_get_all_alarm_logs()
