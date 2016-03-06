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

DEBUG = True

GROUPME_ENABLED = True
GSPREAD_ENABLED = True

HPOT_IDS = [100, 200]
HPOT_IPS = {
    100: '8.8.8.8',
    200: '8.8.8.4'
}

ALLOWED_MINS = 0.25

GDRIVE_CHANGELOG_SPREAD_KEY = None
GDRIVE_CONNECTION_SPREAD_KEYS = None

# These paths are relative to the root of the host
HPOT_ROOT_LOCATION = '/vz/private/'
STORAGE_LOCATION = '/home/hp/hpot-data/'
BACKUP_LOCATION = '/hpot-backup/'
HSSH_ROOT = '/usr/games/.apps/honssh/'
ACTIVE_HPOT_FILE = os.path.join(STORAGE_LOCATION, 'active_honeypots')

# These paths are relative to the root of the honeypot
LOG_FILES = ['/var/log/auth.log', '/usr/games/.logs/valid_passwords.log', '/usr/games/.logs/snoopy.log', '/usr/games/.logs/logger.log']
HSSH_LOG_DIRS = []

# This should be left as None
STATUS_BOT_ID = None

GSPREAD_CLIENT = None

def auth_client():
    global GSPREAD_CLIENT

    if GDRIVE_CHANGELOG_SPREAD_KEY == None:
        __gspread_init()
    
    if GSPREAD_CLIENT == None:
        credential_path = os.path.dirname(os.path.realpath(__file__)) + '/credentials.json'
        scope = ['https://spreadsheets.google.com/feeds']
        credentials = ServiceAccountCredentials.from_json_keyfile_name(credential_path, scope)
        auth = gspread.authorize(credentials)
        GSPREAD_CLIENT = auth
        print('Completed authorization.')
    
    return GSPREAD_CLIENT

def __gspread_init():
    global GDRIVE_CHANGELOG_SPREAD_KEY, GDRIVE_CONNECTION_SPREAD_KEYS
    
    with open('gspread_keys.txt', 'r') as f:
        GDRIVE_CHANGELOG_SPREAD_KEY = f.readline().replace('\n', '')
        GDRIVE_CONNECTION_SPREAD_KEYS = {}
        for hp_id in HPOT_IDS:
            GDRIVE_CONNECTION_SPREAD_KEYS[hp_id] = f.readline().replace('\n', '')
            


def shell_cmd(cmd):
    """Cmd should be the command string to execute. The resulting output is returned.
    """
    proc = subprocess.Popen([cmd], stdout=subprocess.PIPE, shell=True)
    result = proc.stdout.read()
    return result


def shell_cmd_oneline(cmd):
    return shell_cmd(cmd).replace('\n', '')


def groupme_log(message):
    if not GROUPME_ENABLED:
        return

    if STATUS_BOT_ID == None:
        __groupme_init()
    
    shell_cmd_oneline('curl -d \'{"text" : "' + message + '", "bot_id" : "' + STATUS_BOT_ID + '"}\' https://api.groupme.com/v3/bots/post > /dev/null 2>&1')


def __groupme_init():
    """ Reads the file botid.txt to determine the BOT ID to use for logging.
    """
    global STATUS_BOT_ID

    if not GROUPME_ENABLED:
        return

    with open('botid.txt', 'r') as f:
        STATUS_BOT_ID = f.readline().replace('\n', '')

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

def write_session_open(worksheet, open_connection):
    row = find_next_row(worksheet)
    if row is None:
        print('Out of rows. Adding 100 more.')
        worksheet.add_rows(100)
        row = find_next_row(worksheet)

    row_cells = worksheet.range('A' + str(row) + ':E' + str(row))
    row_cells[0].value = std_format_date(open_connection['timestamp'])
    row_cells[2].value = open_connection['ip']
    row_cells[3].value = open_connection['uname']
    row_cells[4].value = open_connection['passwd']
    worksheet.update_cells(row_cells)
    

    
def write_session_close(worksheet, open_connection, close_connection):
    worksheet.update_cell(open_connection['log_line'], 2, std_format_date(close_connection['timestamp']))


def write_changelog_entry(worksheet, event_type, detail_msg):
    """ Trys to log the next entry in the worksheet.
    """
    row = find_next_row(worksheet)
    if row is None:
        print('Out of rows. Adding 100 more.')
        worksheet.add_rows(100)
        row = find_next_row(worksheet)

    row_cells = worksheet.range('A' + str(row) + ':D' + str(row))
    row_cells[0].value = event_type
    row_cells[1].value = 'SCRIPT'
    row_cells[2].value = std_format_date(now_timestamp())
    row_cells[3].value = detail_msg
    worksheet.update_cells(row_cells)

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
            'hssh_store': hssh_store,
        }

    return paths
    
    

def update_tracked_files(paths):
    log_paths = []
    for log in LOG_FILES:
        log = re.sub(r'^/', '', log)
            
        #base_log_paths.append(os.path.join(default_store, os.path.basename(log) + '.default'))        
        log_paths.append({
            'src': os.path.join(paths['hp_root'], log),
            'dest': os.path.join(paths['curr_session_store'], os.path.basename(log))
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

def rsyslog_parse_timestamp(text):
    time = parser.parse(text)
    return time.astimezone(tz.gettz('EST'))

def rsyslog_parse_line(hp_id, text):
    """This is meant to parse lines that have a pid.
    """
    pid = None
    timestamp_str, hostname, program, msg = text.split(' ', 3)
    
    # Remove the ':' from the end of the syslogtag
    program = program[:-1]

    if re.search(r'[a-zA-Z]+\[[0-9]+\]:', text) != None:
        # Syslogtag has a pid number, so parse it out of the program
        program, pid = program.split('[')
               
        #Remove the closing ']'
        pid = pid[:-1]


    line = {
        'type': 'rsyslog',
        'hp_id': hp_id,
        'timestamp': rsyslog_parse_timestamp(timestamp_str),
        'hostname': hostname,
        'program': program,
        'pid': pid,
        'msg': msg
    }
    return line
    

def hssh_parse_timestamp(text):
    time = datetime.strptime(text, '%Y%m%d_%H%M%S_%f')
    timezone_str = shell_cmd_oneline('date +"%Z"')
    time = time.replace(tzinfo=tz.gettz(timezone_str))
    return time.astimezone(tz.gettz('EST'))

def hssh_log_parse_line(hp_id, text, log_name):
    timestamp_str, line_end = text.split(' ', 1)
    tag = re.search(r'\[.*\]', line_end).group(0)
    tag = re.search(r'[A-Z]+', tag).group(0)
    msg = text.split('] ', 1)[1]
    connection_state = None
    ip = None
    port = None

    if tag == 'SSH':
        if 'Incoming Connection' in msg:
            ip, port = msg.rsplit(' ', 1)[1].split(':')
            connection_state = 'OPENED'
        elif 'Lost Connection' in msg:
            ip = msg.rsplit(' ', 1)[1]
            connection_state = 'CLOSED'
        
    line = {
        'type': 'hssh_log',
        'hp_id': hp_id,
        'session_file': log_name,
        'timestamp': hssh_parse_timestamp(timestamp_str),
        'tag': tag,
        'msg': msg,
        'connection_state': connection_state,
        'ip': ip,
        'port': port
    }

    return line
    

def hssh_auth_parse_line(hp_id, text):
    timestamp_str, ip, username, text_end = text.split(',', 3)
    passwd, success = text_end.rsplit(',', 1)
    
    line = {
        'type': 'hssh_auth',
        'hp_id': hp_id,
        'session_file': timestamp_str + '.log',
        'timestamp': hssh_parse_timestamp(timestamp_str),
        'ip': ip,
        'uname': username,
        'passwd': passwd,
        'success': success == 'True',
    }

    return line
    
def hssh_open(parsed_line, open_connections):
    
    if parsed_line == None or parsed_line['type'] != 'hssh_auth':
        return open_connections

    if parsed_line['success']:
        gc = auth_client()
        spread = gc.open_by_key(GDRIVE_CONNECTION_SPREAD_KEYS[parsed_line['hp_id']])
        parsed_line['log_line'] = find_next_row(spread.sheet1)
        open_connections.append(parsed_line)
        hssh_log_open(parsed_line)

    else:
        hssh_log_open_fail(parsed_line)
        
    return open_connections

def hssh_close(parsed_line, open_connections):
    if parsed_line == None or parsed_line['type'] != 'hssh_log':
        return open_connections

    closed_connections = []

    for connection in open_connections:
        if (parsed_line['session_file'] == connection['session_file']
            and parsed_line['ip'] == connection['ip'] and parsed_line['connection_state'] == 'CLOSED'):
            open_connections.remove(connection)
            hssh_log_close(connection, parsed_line)

    return open_connections

def hssh_log_open(open_connection):
    print('Connection opened to ' + open_connection['ip'] + ' at ' + format_time(open_connection['timestamp']) + ' with ' + open_connection['uname'] + ':' + open_connection['passwd'])

    gc = auth_client()
    
    spread = gc.open_by_key(GDRIVE_CHANGELOG_SPREAD_KEY)
    wksht = spread.sheet1
    write_changelog_entry(wksht, 'Compromise Detected', 'Attacker gained access with password ' + open_connection['passwd'])   

    spread = gc.open_by_key(GDRIVE_CONNECTION_SPREAD_KEYS[open_connection['hp_id']])
    wksht = spread.sheet1
    write_session_open(wksht, open_connection)

    groupme_log('Compromise: Attacker gained access with ' + open_connection['uname'] + ':' + open_connection['passwd']])

def hssh_log_open_fail(open_connection):
    print('Failed to connect to ' + open_connection['ip'] + ' at ' + format_time(open_connection['timestamp']) + ' with ' + open_connection['uname'] + ':' + open_connection['passwd'])


def hssh_log_close(open_connection, close_connection):
    print('Connection closed to ' + close_connection['ip'] + ' at ' + format_time(close_connection['timestamp']) + ' opened at ' + format_time(open_connection['timestamp']))

    gc = auth_client()

    spread = gc.open_by_key(GDRIVE_CHANGELOG_SPREAD_KEY)
    wksht = spread.sheet1
    write_changelog_entry(wksht, 'Compromise Resolved', 'Attacker ended session started on ' + std_format_date(open_connection['timestamp']))

    spread = gc.open_by_key(GDRIVE_CONNECTION_SPREAD_KEYS[open_connection['hp_id']])
    wksht = spread.sheet1
    write_session_close(wksht, open_connection, close_connection)
 

def format_date(datetime_obj):
    return datetime_obj.strftime('%a %b %d, %Y')


def format_time(datetime_obj):
    return datetime_obj.strftime('%I:%M:%S %p')
    
def format_time_milis(datetime_obj):
    return datetime_obj.strftime('%I:%M:%S.%f %p')

def parse_line(hp_id, text, log):
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
    elif re.search('^[0-9]{8}_[0-9]{6}_[0-9]{6}\.log$', log_name) != None:
        ptype = 'hssh_log'
    elif 'honssh.log' in log_name:
        ptype = 'hssh_main'
    
    if ptype == 'rsyslog':
        return rsyslog_parse_line(hp_id, text)
    elif ptype == 'passwd':
        return None
    elif ptype == 'hssh_main':
        return None
    elif ptype == 'hssh_auth':
        return hssh_auth_parse_line(hp_id, text)
    elif ptype == 'hssh_log':
        return hssh_log_parse_line(hp_id, text, log_name)

def read_active_honeypots():
    with open(ACTIVE_HPOT_FILE, 'r') as f:
        return f.read().split('\n')[:-1]

def honeypot_logger():
    paths = gen_honeypot_root_dirs()

    hssh_open_connections = {}
    been_compromised = {}
    session_start_time = {}

    session_ip = {}
    force_kick = {}

    if not os.path.exists(ACTIVE_HPOT_FILE):
        with open(ACTIVE_HPOT_FILE, 'w') as f:
            for hp_id in HPOT_IDS:
                f.write(str(hp_id) + '\n')

    for hp_id in HPOT_IDS:
        hssh_open_connections[hp_id] = []
        session_ip[hp_id] = None
        session_start_time[hp_id] = None
        force_kick[hp_id] = False
        been_compromised[hp_id] = False    


    active_hpots = read_active_honeypots()
    prev_active_hpots = None
    while True:
        prev_active_hpots = active_hpots
        active_hpots = read_active_honeypots()
        
        print(active_hpots)       
        for tmp_hp_id in active_hpots:
            if tmp_hp_id not in prev_active_hpots:
                tmp_hp_id = int(tmp_hp_id)
                archive_session(tmp_hp_id, session_ip[tmp_hp_id], paths[tmp_hp_id]['storage_root'])
                session_ip[tmp_hp_id] = None
                firewall_reset(tmp_hp_id)
                start_honssh(tmp_hp_id)

        #for hp_id in active_hpots:
        hp_id = 100

        if session_start_time[hp_id] != None:
            time_diff = session_start_time[hp_id] - now_timestamp()
            print(abs(time_diff).total_seconds())
            if abs(time_diff).total_seconds() >= (ALLOWED_MINS * 60):
                print('Kicking all sessions for honeypot ' + str(hp_id))
                stop_honssh(hp_id)
                force_kick[hp_id] = True

        log_paths = update_tracked_files(paths[hp_id])
        for log in log_paths:
            added_lines = new_lines(log['src'], log['dest'])
            for line in added_lines:
                parsed_line = parse_line(hp_id, line, log)
                hssh_open_connections[hp_id] = hssh_open(parsed_line, hssh_open_connections[hp_id])           
                
                if (not been_compromised[hp_id]) and len(hssh_open_connections[hp_id]) > 0:
                    session_ip[hp_id] = hssh_open_connections[hp_id][0]['ip']
                    session_start_time[hp_id] = now_timestamp()
                    firewall_whitelist(hp_id, session_ip[hp_id])
                    been_compromised[hp_id] = True
                
                hssh_open_connections[hp_id] = hssh_close(parsed_line, hssh_open_connections[hp_id])

        if (len(hssh_open_connections[hp_id]) == 0 and been_compromised[hp_id]) or force_kick[hp_id]:
            force_kick[hp_id] = False
            recycle(hp_id)
            been_compromised[hp_id] = False
            session_start_time[hp_id] = None
        sleep(1)
        

def recycle(hp_id):
    hp_id = str(hp_id)
    print('Triggering recycle for honeypot ' + hp_id)
    active = read_active_honeypots()
    with open(ACTIVE_HPOT_FILE, 'w') as f:
        for old_hp_id in active:
            if hp_id != old_hp_id:
                f.write(old_hp_id + '\n')

    if not DEBUG:
        shell_cmd_oneline('restoreHoneypot ' + str(hp_id))

def firewall_whitelist(hp_id, ip_addr):
    list_dir = '/home/hp/firewall-whitelist'

    if not os.path.exists(list_dir):
        os.makedirs(list_dir)

    with open(os.path.join(list_dir, HPOT_IPS[hp_id]), 'w') as f:
        f.write(ip_addr + '\n')
    
    print('Whitelisting ip ' + ip_addr + ' for honeypot ' + str(hp_id))
    
    if not DEBUG:
        shell_cmd_oneline('runFirewall')


def firewall_reset(hp_id):
    list_dir = '/home/hp/firewall-whitelist'
    file_path = os.path.join(list_dir, HPOT_IPS[hp_id])
    
    if os.path.exists(file_path):
        os.remove(file_path)

    print('Resetting firewall for honeypot ' + str(hp_id))
    
    if not DEBUG:
        shell_cmd_oneline('runFirewall')


def archive_session(hp_id, session_ip, storage_root):
    print('Archiving session for honeypot ' + str(hp_id) + ' from ip ' + session_ip)
    current_session_dir = os.path.join(storage_root, 'current_session')
    archive_dir = os.path.join(storage_root, session_ip)
    if not os.path.exists(archive_dir):
        os.mkdir(archive_dir)

    session_count = len(os.listdir(archive_dir))
    session_count += 1
    session_dir = os.path.join(archive_dir, 'session_' + str(session_count))
    
    hssh_dir = os.path.join(session_dir, 'honssh')
    hssh_session_dir = os.path.join(hssh_dir, session_ip)
    hssh_log_dir = os.path.join(hssh_dir, 'logs')

    hssh_session_dest = os.path.join(session_dir, 'hssh_session')

    shell_cmd_oneline('mv ' + current_session_dir + ' ' + session_dir + '; mkdir ' + current_session_dir)
    shell_cmd_oneline('mv ' + hssh_session_dir + ' ' +  hssh_session_dest)
    shell_cmd_oneline('mv ' + os.path.join(hssh_log_dir, '*') + ' ' +  session_dir + '; rmdir ' + hssh_log_dir)
    shell_cmd_oneline('rmdir ' + hssh_dir + ' > /dev/null 2>&1 || mv ' + hssh_dir + ' ' +  os.path.join(session_dir, 'additional_ip_logins'))

def start_honssh(hp_id):
    print('Starting honssh on honeypot ' + str(hp_id))

    if DEBUG:
        shell_cmd_oneline('cd /usr/games/.apps/honssh/ && ./honsshctrl.sh start')
    else:
        shell_cmd_oneline('vzctl exec 100 ' + os.path.join(HSSH_ROOT, 'honsshctrl.sh') + ' start')
    clear_logs(hp_id)

def stop_honssh(hp_id):
    print('Stopping honssh on honeypot ' + str(hp_id))
    
    if DEBUG:
        shell_cmd_oneline('echo -n "The system is going down for halt NOW!" | wall > /dev/null 2>&1')
        shell_cmd_oneline('cd /usr/games/.apps/honssh/ && ./honsshctrl.sh stop')
    else:
        shell_cmd_oneline('vzctl exec 100 echo -n "The system is going down for halt NOW!" | wall 2>&1')
        shell_cmd_oneline('vzctl exec 100 ' + os.path.join(HSSH_ROOT, 'honsshctrl.sh') + ' stop')


def clear_logs(hp_id):
    print('Clearing logs for heonypot ' + str(hp_id))
    if not DEBUG:
        shell_cmd_oneline('log-clear ' + str(hp_id) + ' > /dev/null 2>&1')

def std_format_date(datetime_obj):
    return datetime_obj.strftime('%a %b %m %H:%M:%S %Z %Y')


def now_timestamp():
    time = datetime.now()
    timezone_str = shell_cmd_oneline('date +"%Z"')
    time = time.replace(tzinfo=tz.gettz(timezone_str))
    return time.astimezone(tz.gettz('EST'))

def print_paths():
    import pprint
    pp = pprint.PrettyPrinter(indent=4)
    paths = gen_honeypot_root_dirs()
    for hp_id in HPOT_IDS:
        files = update_tracked_files(paths[hp_id])
        pp.pprint(files)
    

try:
    if DEBUG:
        print('WARNING: Running in debug mode.')
    honeypot_logger()
except KeyboardInterrupt:
    print('Stopping...')
except:
    groupme_log('Fatal Error: Script Terminating')
    print('Fatal Error: Script Terminating')
    raise
