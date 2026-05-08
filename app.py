from flask import Flask, render_template, request, jsonify
import numpy as np
import pandas as pd
import pickle

app = Flask(__name__)

with open('model/artifacts.pkl', 'rb') as f:
    artifacts = pickle.load(f)

model       = artifacts['model']
scaler      = artifacts['scaler']
FEATURE_COLS= artifacts['feature_cols']
CLASSES     = artifacts['classes']

PROTO_MAP   = {'tcp': 0, 'udp': 1, 'icmp': 2}
SERVICE_MAP = {s: i for i, s in enumerate([
    'aol','auth','bgp','courier','csnet_ns','ctf','daytime','discard','domain',
    'domain_u','echo','eco_i','ecr_i','efs','exec','finger','ftp','ftp_data',
    'gopher','harvest','hostnames','http','http_2784','http_443','http_8001',
    'imap4','IRC','iso_tsap','klogin','kshell','ldap','link','login','mtp',
    'name','netbios_dgm','netbios_ns','netbios_ssn','netstat','nnsp','nntp',
    'ntp_u','other','pm_dump','pop_2','pop_3','printer','private','red_i',
    'remote_job','rje','shell','smtp','sql_net','ssh','ssrp','sunrpc','supdup',
    'systat','telnet','tftp_u','tim_i','time','urh_i','urp_i','uucp',
    'uucp_path','vmnet','whois','X11','Z39_50'
])}
FLAG_MAP = {f: i for i, f in enumerate([
    'OTH','REJ','RSTO','RSTOS0','RSTR','S0','S1','S2','S3','SF','SH'
])}

ATTACK_INFO = {
    'Normal': {
        'color': '#22c55e',
        'bg': '#f0fdf4',
        'border': '#86efac',
        'icon': '✅',
        'description': 'This connection appears to be legitimate network traffic with no signs of malicious activity.',
        'risk': 'None'
    },
    'DoS': {
        'color': '#ef4444',
        'bg': '#fef2f2',
        'border': '#fca5a5',
        'icon': '🔴',
        'description': 'Denial of Service attack detected. The connection shows patterns consistent with attempting to overwhelm network resources.',
        'risk': 'Critical'
    },
    'Probe': {
        'color': '#f97316',
        'bg': '#fff7ed',
        'border': '#fdba74',
        'icon': '🟠',
        'description': 'Probe/Scan attack detected. The connection appears to be scanning for vulnerabilities or open ports.',
        'risk': 'High'
    },
    'R2L': {
        'color': '#a855f7',
        'bg': '#faf5ff',
        'border': '#d8b4fe',
        'icon': '🟣',
        'description': 'Remote to Local attack detected. An external attacker may be attempting to gain unauthorized local access.',
        'risk': 'High'
    },
    'U2R': {
        'color': '#6366f1',
        'bg': '#eef2ff',
        'border': '#a5b4fc',
        'icon': '🔵',
        'description': 'User to Root attack detected. A user may be attempting to escalate privileges to gain root/admin access.',
        'risk': 'Critical'
    },
}

def engineer(df):
    df = df.copy()
    df['src_dst_ratio']        = df['src_bytes'] / (df['dst_bytes'] + 1)
    df['total_bytes']          = df['src_bytes'] + df['dst_bytes']
    df['total_error_rate']     = df['serror_rate'] + df['rerror_rate']
    df['srv_total_error_rate'] = df['srv_serror_rate'] + df['srv_rerror_rate']
    df['host_srv_diversity']   = df['dst_host_srv_count'] / (df['dst_host_count'] + 1)
    return df

@app.route('/')
def index():
    return render_template('index.html',
                           protocols=list(PROTO_MAP.keys()),
                           services=list(SERVICE_MAP.keys()),
                           flags=list(FLAG_MAP.keys()))

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        row = {
            'duration':                    float(data.get('duration', 0)),
            'protocol_type':               PROTO_MAP.get(data.get('protocol_type','tcp'), 0),
            'service':                     SERVICE_MAP.get(data.get('service','http'), 11),
            'flag':                        FLAG_MAP.get(data.get('flag','SF'), 9),
            'src_bytes':                   float(data.get('src_bytes', 0)),
            'dst_bytes':                   float(data.get('dst_bytes', 0)),
            'land':                        int(data.get('land', 0)),
            'wrong_fragment':              int(data.get('wrong_fragment', 0)),
            'urgent':                      int(data.get('urgent', 0)),
            'hot':                         int(data.get('hot', 0)),
            'num_failed_logins':           int(data.get('num_failed_logins', 0)),
            'logged_in':                   int(data.get('logged_in', 1)),
            'num_compromised':             int(data.get('num_compromised', 0)),
            'root_shell':                  int(data.get('root_shell', 0)),
            'su_attempted':                int(data.get('su_attempted', 0)),
            'num_root':                    int(data.get('num_root', 0)),
            'num_file_creations':          int(data.get('num_file_creations', 0)),
            'num_shells':                  int(data.get('num_shells', 0)),
            'num_access_files':            int(data.get('num_access_files', 0)),
            'num_outbound_cmds':           int(data.get('num_outbound_cmds', 0)),
            'is_host_login':               int(data.get('is_host_login', 0)),
            'is_guest_login':              int(data.get('is_guest_login', 0)),
            'count':                       int(data.get('count', 1)),
            'srv_count':                   int(data.get('srv_count', 1)),
            'serror_rate':                 float(data.get('serror_rate', 0)),
            'srv_serror_rate':             float(data.get('srv_serror_rate', 0)),
            'rerror_rate':                 float(data.get('rerror_rate', 0)),
            'srv_rerror_rate':             float(data.get('srv_rerror_rate', 0)),
            'same_srv_rate':               float(data.get('same_srv_rate', 1)),
            'diff_srv_rate':               float(data.get('diff_srv_rate', 0)),
            'srv_diff_host_rate':          float(data.get('srv_diff_host_rate', 0)),
            'dst_host_count':              int(data.get('dst_host_count', 1)),
            'dst_host_srv_count':          int(data.get('dst_host_srv_count', 1)),
            'dst_host_same_srv_rate':      float(data.get('dst_host_same_srv_rate', 1)),
            'dst_host_diff_srv_rate':      float(data.get('dst_host_diff_srv_rate', 0)),
            'dst_host_same_src_port_rate': float(data.get('dst_host_same_src_port_rate', 0)),
            'dst_host_srv_diff_host_rate': float(data.get('dst_host_srv_diff_host_rate', 0)),
            'dst_host_serror_rate':        float(data.get('dst_host_serror_rate', 0)),
            'dst_host_srv_serror_rate':    float(data.get('dst_host_srv_serror_rate', 0)),
            'dst_host_rerror_rate':        float(data.get('dst_host_rerror_rate', 0)),
            'dst_host_srv_rerror_rate':    float(data.get('dst_host_srv_rerror_rate', 0)),
        }
        df = pd.DataFrame([row])
        df = engineer(df)
        df = df[FEATURE_COLS]
        X  = scaler.transform(df)
        probs      = model.predict_proba(X)[0]
        pred_idx   = int(np.argmax(probs))
        pred_class = CLASSES[pred_idx]
        confidence = float(probs[pred_idx])
        all_probs  = {CLASSES[i]: round(float(p)*100, 2) for i, p in enumerate(probs)}
        info = ATTACK_INFO[pred_class]
        return jsonify({
            'prediction':  pred_class,
            'confidence':  round(confidence * 100, 2),
            'all_probs':   all_probs,
            'color':       info['color'],
            'bg':          info['bg'],
            'border':      info['border'],
            'icon':        info['icon'],
            'description': info['description'],
            'risk':        info['risk'],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sample/<attack_type>')
def sample(attack_type):
    samples = {
        'normal': {
            'duration':0,'protocol_type':'tcp','service':'http','flag':'SF',
            'src_bytes':1032,'dst_bytes':4092,'land':0,'wrong_fragment':0,
            'urgent':0,'hot':0,'num_failed_logins':0,'logged_in':1,
            'num_compromised':0,'root_shell':0,'su_attempted':0,'num_root':0,
            'num_file_creations':0,'num_shells':0,'num_access_files':0,
            'num_outbound_cmds':0,'is_host_login':0,'is_guest_login':0,
            'count':10,'srv_count':10,'serror_rate':0.0,'srv_serror_rate':0.0,
            'rerror_rate':0.0,'srv_rerror_rate':0.0,'same_srv_rate':1.0,
            'diff_srv_rate':0.0,'srv_diff_host_rate':0.0,'dst_host_count':255,
            'dst_host_srv_count':255,'dst_host_same_srv_rate':1.0,
            'dst_host_diff_srv_rate':0.0,'dst_host_same_src_port_rate':0.0,
            'dst_host_srv_diff_host_rate':0.0,'dst_host_serror_rate':0.0,
            'dst_host_srv_serror_rate':0.0,'dst_host_rerror_rate':0.0,
            'dst_host_srv_rerror_rate':0.0
        },
        'dos': {
            'duration':0,'protocol_type':'tcp','service':'http','flag':'S0',
            'src_bytes':0,'dst_bytes':0,'land':0,'wrong_fragment':0,
            'urgent':0,'hot':0,'num_failed_logins':0,'logged_in':0,
            'num_compromised':0,'root_shell':0,'su_attempted':0,'num_root':0,
            'num_file_creations':0,'num_shells':0,'num_access_files':0,
            'num_outbound_cmds':0,'is_host_login':0,'is_guest_login':0,
            'count':511,'srv_count':511,'serror_rate':1.0,'srv_serror_rate':1.0,
            'rerror_rate':0.0,'srv_rerror_rate':0.0,'same_srv_rate':1.0,
            'diff_srv_rate':0.0,'srv_diff_host_rate':0.0,'dst_host_count':255,
            'dst_host_srv_count':255,'dst_host_same_srv_rate':1.0,
            'dst_host_diff_srv_rate':0.0,'dst_host_same_src_port_rate':1.0,
            'dst_host_srv_diff_host_rate':0.0,'dst_host_serror_rate':1.0,
            'dst_host_srv_serror_rate':1.0,'dst_host_rerror_rate':0.0,
            'dst_host_srv_rerror_rate':0.0
        },
        'probe': {
            'duration':0,'protocol_type':'icmp','service':'eco_i','flag':'SF',
            'src_bytes':8,'dst_bytes':0,'land':0,'wrong_fragment':0,
            'urgent':0,'hot':0,'num_failed_logins':0,'logged_in':0,
            'num_compromised':0,'root_shell':0,'su_attempted':0,'num_root':0,
            'num_file_creations':0,'num_shells':0,'num_access_files':0,
            'num_outbound_cmds':0,'is_host_login':0,'is_guest_login':0,
            'count':511,'srv_count':25,'serror_rate':0.0,'srv_serror_rate':0.0,
            'rerror_rate':0.0,'srv_rerror_rate':0.0,'same_srv_rate':1.0,
            'diff_srv_rate':0.0,'srv_diff_host_rate':1.0,'dst_host_count':3,
            'dst_host_srv_count':3,'dst_host_same_srv_rate':1.0,
            'dst_host_diff_srv_rate':0.0,'dst_host_same_src_port_rate':1.0,
            'dst_host_srv_diff_host_rate':1.0,'dst_host_serror_rate':0.0,
            'dst_host_srv_serror_rate':0.0,'dst_host_rerror_rate':0.0,
            'dst_host_srv_rerror_rate':0.0
        },
    }
    return jsonify(samples.get(attack_type, samples['normal']))

if __name__ == '__main__':
    app.run(debug=True)
