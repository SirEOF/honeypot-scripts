#!/usr/bin/env python

import os
import subprocess
from datetime import datetime
from dateutil import parser
from dateutil import tz
from time import sleep
import re

import gspread
from oauth2client.service_account import ServiceAccountCredentials


HPOT_IDS = [100, 200]

#These paths are relative to the root of the host
HPOT_ROOT_LOCATION = '/vz/private/'
STORAGE_LOCATION = '/home/hp/hpot-data/'
BACKUP_LOCATION = '/hpot-backup/'
HSSH_ROOT = '/usr/games/.apps/honssh/'

#These paths are relative to the root of the honeypot
LOG_FILES = ['/var/log/auth.log', '/usr/games/.logs/valid_passwords.log']
HSSH_LOG_DIRS = []

def authorize_client():
    credential_path = os.path.dirname(os.path.realpath(__file__)) + '/credentials.json'
    scope = ['https://spreadsheets.google.com/feeds']
    credentials = ServiceAccountCredentials.from_json_keyfile_name(credential_path, scope)
    auth = gspread.authorize(credentials)
    print('Completed authorization.')
    return auth

def shell_cmd(cmd):
    """Cmd should be the command string to execute. The resulting output is returned.
    """
    proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
    result = proc.stdout.read()
    return result

def shell_cmd_oneline(cmd):
    return shell_cmd(cmd).replace('\n', '')


def disk_space():
    return shell_cmd_oneline('df -h | head -n2 | tail -n1 | cut -c30- | cut -d" " -f1')


def find_next_row(worksheet):
    """ Finds the first empty row of the worksheet.
    """
    val_list = worksheet.col_values(1)
    row_num = 1
    for row in val_list:
        if row == '':
            return row_num
        row_num += 1
    return None

def write_entry(worksheet):
    """ Trys to log the next entry in the worksheet.
    """
    row = find_next_row(worksheet)
    if row is None:
        print('Out of rows. Adding 100 more.')
        worksheet.add_rows(100)
        row = find_next_row(worksheet)
    print('Writing data to row ' + str(row) + '.')
    row_cells = worksheet.range('A' + str(row) + ':C' + str(row))
    row_cells[0].value = shell_cmd('date')
    row_cells[1].value = disk_space()
    row_cells[2].value = 'test'
    worksheet.update_cells(row_cells)
    print('Row written.')
    return True

#line = shell_cmd('date') + ',' + disk_space() + ',' + shell_cmd('uptime | cut -d" " -f11')

#print(line)


#gc = authorize_client()
#spread = gc.open_by_key('1k8ZSXOlcGadSFfU8uJLzDMi6Ksr88ZBP6hZe0MWM-18')
#wks = spread.sheet1
#print('1min: ' + shell_cmd('uptime | cut -d" " -f10'))
#print('5min: ' + shell_cmd('uptime | cut -d" " -f11'))
#print('15min: ' + shell_cmd('uptime | cut -d" " -f12'))
#write_entry(wks)

def new_lines(file_path, file_backup_path):
    if not os.path.exists(file_backup_path):
        shell_cmd_oneline('mkdir -p ' + os.path.dirname(file_backup_path))
        shell_cmd_oneline('touch ' + file_backup_path)        
    
    if not os.path.exists(file_path):
        return []

    out = shell_cmd('diff ' + file_path + ' ' + file_backup_path + '| grep "^< " | cut -c3- | tee -a ' + file_backup_path)
    out = out.split('\n')
    out = out[:-1]
    return out

def gen_honeypot_root_dirs():
    global HSSH_LOG_DIRS

    paths = {}
    for hp_id in HPOT_IDS:
        hp_root = os.path.join(HPOT_ROOT_LOCATION, str(hp_id))
        storage_root = os.path.join(STORAGE_LOCATION, str(hp_id))
        default_store = os.path.join(storage_root, 'default')        
        curr_session_store = os.path.join(storage_root, 'current_session')
        hssh_store = os.path.join(curr_session_store, 'honssh')

        if not os.path.exists(hp_root):
            os.makedirs(hp_root)

        if not os.path.exists(storage_root):
            os.makedirs(storage_root)
        
        if not os.path.exists(default_store):
            os.makedirs(default_store)
        
        if not os.path.exists(curr_session_store):
            os.makedirs(curr_session_store)
        
        if not os.path.exists(hssh_store):
            os.makedirs(hssh_store)
            
        
        #Add the directories for the session folder in honSSH
        hssh_root = re.sub(r'^/', '', HSSH_ROOT)
        hssh_root = os.path.join(hp_root, hssh_root)
        
        if os.path.exists(hssh_root):
           
            ######
            # Logs
            hssh_log = os.path.join(hssh_root, 'logs/')
            HSSH_LOG_DIRS.append(hssh_log.replace(hp_root, ''))

                
            #########
            # Session
            hssh_session = os.path.join(hssh_root, 'sessions/')
            
            #Navigate down the honeypot identifier dir
            hssh_host_dir = os.path.join(hssh_session, os.listdir(hssh_session)[0])
            hssh_add_dirs = os.listdir(hssh_host_dir)
            
            #Navigate down through the ip address directories for each session
            for session_dir in hssh_add_dirs:
                HSSH_LOG_DIRS.append(os.path.join(hssh_host_dir, session_dir).replace(hp_root, ''))

        paths[hp_id] = {
            'hp_root': hp_root,
            'storage_root': storage_root,
            'default_store': default_store,
            'curr_session_store': curr_session_store,
            'hssh_store': hssh_store
        }

    return paths
    
    

def update_tracked_files(paths):
    log_paths = []
    for log in LOG_FILES:
        log = re.sub(r'^/', '', log)
            
        #base_log_paths.append(os.path.join(default_store, os.path.basename(log) + '.default'))        
        log_paths.append({
            'src': os.path.join(paths['hp_root'], log),
            'dest': os.path.join(paths['curr_session_store'], os.path.basename(log) + '.bk')
        })

    for log_dir in HSSH_LOG_DIRS:
        log_dir = re.sub(r'^/', '', log_dir)
        log_dir = re.sub(r'/$', '', log_dir)
        dir_name = os.path.basename(log_dir)
        
        abs_log_dir = os.path.join(paths['hp_root'], log_dir)
        
        if os.path.exists(abs_log_dir):
            dir_files = os.listdir(abs_log_dir)
            
            for dir_file in dir_files:
                if re.search('^[0-9]{8}$', dir_file) == None:
                    log_paths.append({
                        'src': os.path.join(abs_log_dir, dir_file),
                        'dest': os.path.join(paths['hssh_store'], dir_name + '/' + dir_file)
                    })
                else:
                    log_paths.append({
                        'src': os.path.join(abs_log_dir, dir_file),
                        'dest': os.path.join(paths['hssh_store'], dir_name + '/' + 'hssh-auth.log')
                    })
                
    return log_paths
    

def ssh_open(parsed_line, open_connections):
    """ Returns an array of open_connections with any new connections added.
    """
    
    if parsed_line == None or parsed_line['type'] != 'rsyslog':
        return open_connections

    if parsed_line['program'] != 'sshd':
        return open_connections

    msg = parsed_line['msg']

    if 'Accepted' not in msg:
        return open_connections


    split_msg = msg.split(' ')
    connection = {
        'ip': split_msg[5],
        'pid': parsed_line['pid'],
        'timestamp': parsed_line['timestamp']
    }
    
        
    ssh_log_open(connection)
    open_connections.append(connection)
    return open_connections    

def ssh_close(parsed_line, open_connections):
    """ Returns open_connections with any closed connections removed.
    """    
    
    if parsed_line == None or parsed_line['type'] != 'rsyslog':
        return open_connections

    if parsed_line['program'] != 'sshd' or len(open_connections) == 0:
        return open_connections

    msg = parsed_line['msg']

    closed_connections = []

    if 'pam_unix(sshd:session): session closed for user' in msg:
        for connection in open_connections:
            if connection['pid'] == parsed_line['pid']:
                closed_connections.append(connection)
                open_connections.remove(connection)
    
    for connection in closed_connections:
        ssh_log_close(connection)    
    return open_connections


def ssh_log_open(connection):
    print('Opened connection with pid ' + str(connection['pid']))

def ssh_log_close(connection):
    print('Closed connection with pid ' + str(connection['pid']))

def hssh_open(parsed_line, open_connections):
    
    if parsed_line == None or parsed_line['type'] != 'hssh_log' or parsed_line['type'] != 'hssh_auth':
        return open_connections
        
    return open_connections

def hssh_close(parsed_line, open_connections):
    
    if parsed_line == None or parsed_line['type'] != 'hssh_log' or parsed_line['type'] != 'hssh_auth':
        return open_connections
        
    return open_connections

def rsyslog_parse_timestamp(text):
    time = parser.parse(text)
    return time.astimezone(tz.gettz('EST'))

def rsyslog_parse_line(text):
    """This is meant to parse lines that have a pid.
    """
    
    program_info, msg = text.split(']: ', 1)
    timestamp_str, hostname, program = program_info.split(' ')
    program, pid = program.split('[')
    line = {
        'type': 'rsyslog',
        'timestamp': timestamp_str,
        'hostname': hostname,
        'program': program,
        'pid': pid,
        'msg': msg
    }
    return line

def filecount_change(old_file_count, directory):
    return len(os.listdir(directory)) == old_file_count

def hssh_parse_file_timestamp(text):
    time = datetime.strptime(text, '%Y%m%d_%H%M%S_%f')
    timezone_str = shell_cmd_oneline('date +"%Z"')
    time = time.replace(tzinfo=tz.gettz(timezone_str))
    return time.astimezone(tz.gettz('EST'))

def hssh_log_parse_line(text):
    tmp_date, tmp_time, line_end = text.split(' ', 2)
    line_end = re.sub(r' *[HonsshServerTransport.*] ', '', line_end)
    print(line_end)    

def hssh_auth_parse_line(text):
    
    timestamp_str, ip, username, text_end = text.split(',', 3)
    passwd, sucess = text_end.rsplit(',', 1)

    line = {
        'type': 'hssh_auth',
        'timestamp': hssh_parse_file_timestamp(timestamp_str),
        'ip': ip,
        'user': username,
        'passwd': passwd,
        'sucess': bool(sucess)
    }

    return line
    

def format_date(datetime_obj):
    return datetime_obj.strftime('%a %b %d, %Y')

def format_time(datetime_obj):
    return datetime_obj.strftime('%I:%M:%S.%f %p')

def parse_line(text, log):
    log_name = os.path.basename(log['src'])
    ptype = ''
    if 'auth.log' in log_name:
        ptype = 'rsyslog'
    elif 'snoopy' in log_name:
        ptype = 'rsyslog'
    elif 'password' in log_name:
        ptype = 'passwd'
    elif re.search('^[0-9]{8}$', log_name) != None:
        ptype = 'hssh_auth'
    elif 'honssh.log' in log_name:
        ptype = 'hssh_log'
    
    if ptype == 'rsyslog':
        return rsyslog_parse_line(text)
    elif ptype == 'passwd':
        return None
    elif ptype == 'hssh_auth':
        return hssh_auth_parse_line(text)
    elif ptype == 'hssh_log':
        return hssh_log_parse_line(text)

def honeypot_logger():
    paths = gen_honeypot_root_dirs()
    #for hp_id in HPOT_IDS
    hp_id = 100

    ssh_open_connections = []
    hssh_open_connections = []
    while True:
        log_paths = update_tracked_files(paths[hp_id])
        for log in log_paths:
            added_lines = new_lines(log['src'], log['dest'])
            for line in added_lines:
                parsed_line = parse_line(line, log)
                ssh_open_connections = ssh_open(parsed_line, ssh_open_connections)
                ssh_open_connections = ssh_close(parsed_line, ssh_open_connections)
                hssh_open_connections = hssh_open(parsed_line, hssh_open_connections)           
                hssh_open_connections = hssh_close(parsed_line, hssh_open_connections)
        sleep(1)


def print_paths():
    import pprint
    pp = pprint.PrettyPrinter(indent=4)
    paths = gen_honeypot_root_dirs()
    for hp_id in HPOT_IDS:
        files = update_tracked_files(paths[hp_id])
        pp.pprint(files)
    

#lines = new_lines('/var/log/auth.log', '/root/auth.log.bk')

#mydate = parse_timestamp(parse_line(lines[-1])[0])
#print(format_date(mydate))
#print(format_time(mydate))

#pp.pprint(gen_honeypot_paths()[100])

honeypot_logger()

#print(hssh_parse_timestamp('20160302_182957_730500'))
#print(hssh_parse_line('20160304_203711_950503,127.0.0.1,test,,,False'))
