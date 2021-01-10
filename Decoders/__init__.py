import os
import requests
from bs4 import BeautifulSoup
import pandas as pd
from datetime import datetime
from pythonping import ping
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dirsync import sync

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
# nevion_management_ips = [
#     '172.16.11.235',
#     '172.17.226.102',
#     '172.18.6.110',
#     '172.18.6.111',
#     '172.19.6.180',
#     '172.23.6.160',
#     '172.24.6.62',
#     '172.31.18.2',
#     '172.31.23.4',
#     '192.168.117.27',
#     '192.168.128.34',
#     '192.168.13.30',
#     '192.168.25.205',
#     '192.168.37.40',
#     '192.168.62.100',
#     '192.168.63.100',
#     '192.168.64.100',
#     '192.168.65.100',
#     '192.168.66.100',
#     '192.168.67.100',
#     '192.168.68.100',
#     '192.168.70.100',
#     '192.168.73.100',
#     '192.168.75.100'
# ]
decoders_nevions_management_ips = ['172.23.6.160',
                                   # '192.168.61.110',
                                   '192.168.69.100',
                                   '172.17.226.102',
                                   '192.168.70.100',
                                   '192.168.73.100',
                                   '192.168.73.100',
                                   '192.168.68.100',
                                   '192.168.25.205',
                                   '192.168.60.100',
                                   '172.25.5.100',
                                   # '192.168.67.10',
                                   # '192.168.129.19',
                                   '192.168.119.218',
                                   '192.168.117.27',
                                   '192.168.37.40',
                                   '192.168.65.100',
                                   '192.168.64.100',
                                   '192.168.66.100',
                                   '172.16.11.235',
                                   '172.16.11.233',
                                   '172.16.11.237',
                                   '172.24.6.62',
                                   '172.31.23.4',
                                   '192.168.13.30',
                                   '192.168.63.100',
                                   '192.168.62.100',
                                   '172.31.18.2',
                                   '172.18.6.110',
                                   '172.19.6.180',
                                   '172.19.6.181',
                                   '192.168.77.100']
alarm_log_head = 'Decoder name,On time,Off time,Sequence#,Severity#,Severity,Type,Alarm ID,Text,Source,Subid1,Subid2,' \
                 'Subid3,Details'
alarm_log_head_with_decoder_name = 'Decoder name,On time,Off time,Sequence#,Severity#,Severity,Type,Alarm ID,Text,' \
                                   'Source,Subid1,Subid2,Subid3,Details'


def decoder_name(management_ip):
    try:
        method = 'http://'
        txp_call = '/txp_get?path=/dev/product_info|_select:devname'
        req = requests.get(method + management_ip + txp_call)
        soup = BeautifulSoup(req.content, 'lxml')
        x = soup.find('product_info')
        name = x.get('devname')
        # print('Console: ' + name)
        return name
    except TimeoutError as error:
        print(error)


def decoder_date():
    try:
        todays_date = datetime.now().strftime('%y%m%d')  # 201228
        return todays_date
    except Exception as error:
        print(error)


def decoder_date_and_time():
    todays_date_and_time = datetime.now().strftime('%y-%m-%d' + '_' + '%H_%M_%S')  # 201228
    return todays_date_and_time


def decoder_date_and_time_american_style():
    try:
        todays_date_and_time = datetime.now().strftime('%m-%d-%y' + '_' + '%H:%M:%S')  # 201228
        return todays_date_and_time
    except Exception as error:
        print(error)


def decoder_date_year_first():
    try:
        todays_date_2020_first = datetime.now().strftime('%Y-%m-%d')  # 2020-12-28
        return todays_date_2020_first
    except Exception as error:
        print(error)


def decoder_nevion_ping_robot():
    try:
        with open('nevion ping logs.csv', 'w')as ping_log:
            ping_log.write(str(decoder_date()) + '\n')
            ping_results = []
            for management_ip in decoders_nevions_management_ips:
                print(ping(management_ip, count=4, verbose=True))
                print('Nevion Allocated to: ' + decoder_name(management_ip))
                x = ping(management_ip)
                print(x)
                ping_log.write(str(ping(management_ip, count=1, verbose=True)))
                h = str(ping(management_ip))
                ping_results.append(h)
                pings = ping_results

        return pings
    except TimeoutError as error:
        print(error)
        pass


def decoder_email_alert_notification(sender_email, receiver_email, subject, message_text):
    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = sender_email
        message["To"] = receiver_email
        # write the plain text part

        message_text = MIMEText(message_text, "plain")
        # email_message_html = MIMEText(email_message_html, "html")
        message.attach(message_text)
        # message.attach(email_message_html)
        # send your email
        with smtplib.SMTP("172.16.5.9", 25) as server:
            server.sendmail(sender_email, receiver_email, message.as_string())
        print('Sent')
    except TimeoutError as error:
        print(error)
    return


def decoder_lock_status(management_ip):
    try:
        method = 'http://'
        txp_call = '/txp_get?path=/ports/ip_input|select=*/iprx/buff|_select:locked'
        req = requests.get(method + management_ip + txp_call)
        soup = BeautifulSoup(req.content, 'lxml')
        x = soup.find('buff')
        locked_state = x.get('locked')
        x = locked_state.title()
        return x
    except TimeoutError as e:
        print(e)
        pass


def decoder_actual_latency(management_ip):
    try:
        method = 'http://'
        txp_call = '/txp_get?path=/ports/ip_input|select=*/iprx/buff|_select:act_latency'
        req = requests.get(method + management_ip + txp_call)
        soup = BeautifulSoup(req.content, 'lxml')
        x = soup.find('buff')
        a_latency = x.get('act_latency')
        act_latency = a_latency
        return act_latency
    except TimeoutError as e:
        print(e)
        pass


def decoder_last_10_alarms_log(management_ip):
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=10'
        req = requests.get(method + management_ip + txp_call)
        # print('Console:______________')
        print(req.text)
        data = req.text
        return data
    except TimeoutError as e:
        print(e)
        pass


def decoder_last_20_alarms(management_ip):
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=20'
        req = requests.get(method + management_ip + txp_call)
        # print('Console:__________________________')
        print(req.text)
        data = req.text
        return data
    except TimeoutError as e:
        print(e)
        pass


def decoder_get_name_actual_latency_and_lock_status():
    with open('G:/My Drive/Centralization - Nevion Alarm Logs/' + str(
            decoder_date_and_time()) + '-Nevion Lock Status.csv',
              'w')as f:
        print('E.R.I.C.A. | Decoder Lock Status and Latency Report. ' + decoder_date_and_time_american_style())
        f.write('E.R.I.C.A. | Decoder Lock Status and Latency Report. Date & Time' + decoder_date_and_time_american_style())
        print('EAP-ID: DEC-00001011' + '\n')
        f.write('EAP-ID: DEC-00001011' + '\n')
        try:
            f.write('Call_Letter_Allocation,IP Transport Stream Lock Status,' + str(decoder_date_and_time_american_style()) + '\n')
            for management_ip in decoders_nevions_management_ips:
                name = decoder_name(management_ip)
                actual_latency = decoder_actual_latency(management_ip)
                locked = decoder_lock_status(management_ip)
                todays_date = str(decoder_date_and_time_american_style())
                print('Nevion Device Name: ' + name + ',', 'Actual Latency: ' + actual_latency + 'ms' + ',', 'Transport Lock State:' + locked,
                      'Date and Time: ' +
                      todays_date + ',', 'Management IP Address: ' + management_ip + '.')

                f.write('Nevion Device Name: ' + name + ',')
                f.write('Actual Latency: ' + actual_latency + ',')
                f.write('Transport Lock State: ' + locked + ',')
                f.write('Date and Time: ' + todays_date + ',')
                f.write('Management IP Address: ' + management_ip + ',')
                f.write('_____________(END of Data______________' + '\n')
                print('............')

            if locked == 'false':
                print('________________________________________________________________________________________\n')
                print('Warning!! The Following Nevion TVG425 IP-STLs are reporting a lock status of FALSE: \n')
                print('Current Transport Stream Lock State: ' + str(locked).title() + '\n')
                f.write(name + ',' + actual_latency + ',' + locked + ',' + todays_date + ',' + management_ip + ',' + '\n')
                print('_____________(END of Data______________' + '\n')
                f.write('_____________(END of Data______________' + '\n')
                return name + 's Nevion has a current lock status of ' + str(locked).title()
        except TimeoutError as error:
            print(error)

        return f.close()


decoder_get_name_actual_latency_and_lock_status()
exit()


def decoder_last_50_alarms(management_ip):
    decoders = []
    for management_ip in decoders_nevions_management_ips:
        decoder_name_and_lock_status = decoder_get_name_actual_latency_and_lock_status()
        decoders.append(decoder_name_and_lock_status)
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=50'
        req = requests.get(method + management_ip + txp_call)
        # print('Console:__________________________')
        print(req.text)
        data = req.text
        return data
    except TimeoutError as e:
        print(e)
        pass


def decoder_last_100_alarms(management_ip):
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=100'
        req = requests.get(method + management_ip + txp_call)
        # print('Console:__________________________')
        print(req.text)
        data = req.text
        return data
    except TimeoutError as e:
        print(e)
        pass


def decoder_last_100_alarms_line_output():
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=100'
        with open('G:/My Drive/Centralization - Nevion Alarm Logs/Nevion Alarm Logs.csv', 'w') as f:
            for management_ip in decoders_nevions_management_ips:
                alarm_log_header_name = decoder_name(management_ip)
                req = requests.get(method + management_ip + txp_call)
                data = req.iter_lines(decode_unicode=True)
                name = alarm_log_header_name
                f.write(alarm_log_head + '\n')
                for line in data:
                    f.write(name + ',' + line.strip() + '\n')
            f.close()
            return print(os.listdir('G:/My Drive/Centralization - Nevion Alarm Logs/'))
    except TimeoutError as e:
        print(e)
        pass


def decoder_last_100_alarms_line_output_no_headers():
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=100'
        with open('G:/My Drive/Centralization - Nevion Alarm Logs/Nevion Alarm Logs' + str(
                decoder_date_and_time_american_style()) + ' .csv', 'w') as f:
            for management_ip in decoders_nevions_management_ips:
                req = requests.get(method + management_ip + txp_call)
                data = req.iter_lines(decode_unicode=True)
                name = decoder_name(management_ip)
                for line in data:
                    f.write(name + ',' + line.strip() + '\n')
            f.close()
            return print(os.listdir('G:/My Drive/Centralization - Nevion Alarm Logs/'))
    except TimeoutError as e:
        print(e)
        pass


def decoder_email_alert_notification_II(sender_email, receiver_email, subject, email_message_html):
    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = sender_email
        message["To"] = receiver_email
        message_text = """
        ERICA - Automation Systems - Alert! (Test)
        """
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
    return


def cloud_alarm_bot():
    decoder_last_100_alarms_line_output_no_headers()
    return


def prep_alarm_log_csv():
    method = 'http://'
    txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=100'
    with open('G:/My Drive/Centralization - Nevion Alarm Logs/Alarm Logs/' + 'Decoders_Alarms_' + str(
            decoder_date_and_time_american_style()) + ' .csv', 'w') as f:
        f.write(alarm_log_head)
        for management_ip in decoders_nevions_management_ips:
            req = requests.get(method + management_ip + txp_call)
            data = req.iter_lines(decode_unicode=True)
            name = decoder_name(management_ip)
            for line in data:
                f.write(name + ',' + line.strip() + '\n')
        f.close()
    log = 'G:/My Drive/Centralization - Nevion Alarm Logs/Nevion Alarm Logs.csv'
    email_message = []
    if log:
        panda = pd.read_csv(log, header=0, usecols=[0, 1, 2, 3, 4, 5, 9, 13])
        for index, row in panda.iterrows():
            email_message.append(row.head())
            print(row)
            return decoder_email_alert_notification('Decoders@entravision.com',
                                                    'mmedina@entravision.com',
                                                    'Nevion Alarm Logs - Critical', str(email_message))


def decoder_all_alarms(management_ip):
    try:
        method = 'http://'
        txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit='
        req = requests.get(method + management_ip + txp_call)
        # print('Console:__________________________' + req.text)
        data = req.text
        return data
    except TimeoutError as e:
        print(e)
        pass


def decoder_generate_all_alarms_individual_csv_file(management_ip):
    ini_path = 'G:/My Drive/Centralization - Nevion Alarm Logs/By Call Letters/'
    date = str(decoder_date())
    with open(ini_path + str(decoder_name(management_ip)) + '_Nevion_Alarm_log_' + date + '.csv',
              'w') as log:
        try:
            method = 'http://'
            txp_call = '/get_alarm_log?&header=true&delimiter=,&offset=0&limit=1000'
            req = requests.get(method + management_ip + txp_call)
            log.write(req.text)
            log.close()

            data = req.text
            return data
        except TimeoutError as e:
            print(e)
            pass


def decoder_nevion_alarms_csv(management_ip):
    with open('D:/Nevion Data/Nevion Alarms/Nevion_Alarm_Logs_' + decoder_name(management_ip) + '_' + str(
            decoder_date()) + '.csv', 'w') as f:
        f.write(alarm_log_head)
        f.write(decoder_last_100_alarms(management_ip))
        return f.close()


def decoder_nevion_alarms_stdout():
    with open('nevion_alarms_103120.csv', 'w') as f:
        for management_ip in decoders_nevions_management_ips:
            f.write(alarm_log_head)
            f.write(decoder_name(management_ip) + '\n')
            f.write('Date of Report: ' + decoder_date() + '\n')
            print('Nevion Call Sign Allocation: ' + decoder_name(management_ip) + '\n')
            f.write(decoder_last_10_alarms_log(management_ip) + '\n')
            print(decoder_last_100_alarms(management_ip) + '\n')
            f.write(decoder_last_100_alarms(management_ip) + '\n')
            print('Nevion IP TS Locked? ' + decoder_lock_status(management_ip) + '\n')
            f.write(decoder_lock_status(management_ip) + '\n')
        return f.close()


def decoder_analyze_nevions(management_ip):
    ini_path = 'D:/ERICA Data/Data/Decoders/Nevions TVG425 Alarms/'
    # nevion_lock_status = decoder_lock_status(management_ip)
    log_dir = os.listdir(ini_path)
    # nevion_name = decoder_name(management_ip)
    for log in log_dir:
        log = pd.read_csv(ini_path + log, delimiter=',', header=0)
        print('_____________________________________________________________________________________________________\n')
        # print('E.R.I.C.A | Decoders - Critical Alarms - Severity# 6 | ' + str(nevion_name))
        # print('Decoder has a lock?:' + nevion_lock_status)
        print('_' * 40)
        with open(
                ini_path + '/' + 'Nevion_Critical_Alarms__' + str(decoder_date()) + '_' + decoder_name(
                    management_ip) + '.csv',
                'w') as critical_log:
            critical_log.write('On time,Off Time,Severity,Source,Text' + '\n')
            for index, row in log.iterrows():
                if row['Severity'] == 'Critical':
                    critical_log.write('On time: ' + str(row['On time']) + ',' + 'Off Time: ' + str(
                        row['Off time']) + ',' + 'Severity: ' +
                                       str(row['Severity']) + ',' + 'Source: ' + str(
                        row['Source']) + ',' + 'Text: ' + str(row['Text']) + '\n')
                if row['Severity'] == 'Critical':
                    print('On time: ' + row['On time'] + ',',
                          'Off Time: ' + row['Off time'] + ',' + 'Source: ' + str(row['Source']),
                          'Text: ' + str(row['Text']))


def decoders_analyze_alarm_events(management_ip):
    ini_path = 'D:/ERICA Data/Data/Decoders/Nevions TVG425 Alarms/'
    log_dir = os.listdir(ini_path)
    nevion_name = decoder_name(management_ip)
    try:
        for log in log_dir:
            print('here')
            locked = decoder_lock_status(management_ip)
            x = pd.read_csv(ini_path + log, header=0, delimiter=',')
            with open('Critical ' + nevion_name + str(decoder_date()) + '.csv', 'w') as critical_log:
                critical_log.write('On time,Off Time,Severity,Source,Text' + '\n')
                for index, row in x.iterrows():
                    if row['Severity'] == 'Critical':
                        critical_log.write('On time: ' + str(row['On time']) + ',' + ' Off Time: ' + str(
                            row['Off time']) + ',' + ' Severity: ' + str(row['Severity']) + ',' + ' Source: ' + str(
                            row['Source']) + ',' + ' Text: ' + str(row['Text']) + 'AlARM ID NUMBER: ' + str(
                            ['Alarm ID']) + '\n')
                    if row['Severity'] == 'Critical:':
                        print('On time: ' + str(row['On time']) + ',' + ' Off Time: ' + str(
                            row['Off time']) + ',' + ' Severity: ' + str(row['Severity']) + ',' + ' Source: ' + str(
                            row['Source']) + ',' + ' Text: ' + str(row['Text']) + 'AlARM ID NUMBER: ' + str(
                            ['Alarm ID']) + '\n')
                    if not locked:
                        print(
                            'URGENT! Nevion TVG 425 allocated to: ' + nevion_name + ' is currently not locked. IP: ' + management_ip + '\n')
                        print(row)
    except Exception as error:
        print(error)
    return print(os.listdir(ini_path))


def sync_decoder_logs_to_cloud():
    cloud_path = 'G:/My Drive/Centralization - Nevion Alarm Logs/'
    local_src_path = 'D:/Nevion Data/Nevion Alarms/'
    sync(local_src_path, cloud_path, 'sync', purge=False)


def decoders_analyze_with_pandas():
    for management_ip in decoders_nevions_management_ips:
        decoder_nevion_alarms_csv(management_ip)
    return decoder_get_name_actual_latency_and_lock_status()


def get_full_logs():
    for management_ip in decoders_nevions_management_ips:
        decoder_generate_all_alarms_individual_csv_file(management_ip)
    return


# Run Function below.

decoder_nevion_ping_robot()
prep_alarm_log_csv()
get_full_logs()
