#!/var/www/dhcp/venv/bin/python
#
# Antoine LOISEAU <a.loiseau@outremer-telecom.fr>
#
# DHCP Admin Application - control and manage OMT dhcp servers
#
# - Records mac and users associated to each computer (sqlite)
# - Generate and send (with ansible) dhcp leases files
#
############### BEGIN ################

import sqlite3
#import csv
import ansible.runner
from flask import Flask, render_template, request, session, flash, redirect, url_for, g, make_response
app = Flask(__name__)

###### INIT App ######################
app = Flask(__name__)
app.secret_key = 'A0ZrAdcs&*sc45#$^s6:w32rf3c7$8ew68fwqERGFeRHnbm3(*23bb@#$%'
DATABASE = '/var/lib/sqlite3/dhcp_admin/dhcp_admin.db'

###### Roles #########################
app.config['USERNAME_ro'] = 'ro'
app.config['PASSWORD_ro'] = 'inf0t3l!'
app.config['USERNAME_rw'] = 'dhcp'
app.config['PASSWORD_rw'] = 'inf0t3l!'
app.config['USERNAME_adm'] = 'admin'
app.config['PASSWORD_adm'] = 'inf0t3l!'

###### Functions #####################

def gen_file():
    f = open('/tmp/dhcp.out', 'w')

    results = query_db('SELECT c.name,upper(u.LName),upper(substr(u.FName,1,1))||lower(substr(u.FName,2)),c.mac,c.subnet,c.sufix,c.wifi FROM computers as c, users as u where c.id_user = u.id_user')

    for host in results:
        f.write('Host ' + host[0])
        if host[6] == 1: 
            f.write('-WIFI')
        f.write(' { # ' + host[1] + ' ' + host[2] + '\n')
        f.write('   hardware ethernet ' + host[3] + '; #\n') 
        f.write('   fixed-address 10.%%.' + str(host[4]) + '.' + str(host[5]) + '; #\n') 
        f.write('}\n')
        f.write('\n')

    f.close()

def ansible_run(ansible_module, ansible_modules_args, dom):
    results = ansible.runner.Runner(
            pattern=dom, forks=15,
            remote_user='root',
            module_name=ansible_module, module_args=ansible_modules_args, private_key_file='/home/ansible/.ssh/id_dsa'
        ).run()    
    return results

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    get_db().commit()
    cur.close()
    return (rv[0] if rv else None) if one else rv

############### ROUTES ###############

####### Globals (all profiles) #######

@app.route('/')
def home():
    # am I logged ?
    if 'logged_ro_in' in session or 'logged_rw_in' in session or 'logged_adm_in' in session:
	all = None
        return render_template('home.html', all=all)
    # or not !
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] == app.config['USERNAME_ro'] and request.form['password'] == app.config['PASSWORD_ro']:
            session['logged_ro_in'] = True
            flash('You were logged in read-only profile')
            return redirect(url_for('home'))
        elif request.form['username'] == app.config['USERNAME_rw'] and request.form['password'] == app.config['PASSWORD_rw']:
            session['logged_rw_in'] = True
            flash('You were logged in read-write profile')
            return redirect(url_for('home'))
        elif request.form['username'] == app.config['USERNAME_adm'] and request.form['password'] == app.config['PASSWORD_adm']:
            session['logged_adm_in'] = True
            flash('You were logged in admin profile')
            return redirect(url_for('home'))
	else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_ro_in', None)
    session.pop('logged_rw_in', None)
    session.pop('logged_adm_in', None)
    flash('You were logged out')
    return redirect(url_for('login'))

##### Read-Only available routes #####

@app.route('/search')
def search():
    # am I logged ?
    if 'logged_ro_in' in session or 'logged_rw_in' in session or 'logged_adm_in' in session:
        return render_template('search.html')
    # or not !
    else:
        return redirect(url_for('login'))

@app.route('/view')
def view():
    # am I logged ?
    if 'logged_ro_in' in session or 'logged_rw_in' in session or 'logged_adm_in' in session:
        all = query_db('SELECT c.id_comp,c.name,c.mac,c.subnet,c.sufix,upper(substr(u.FName,1,1))||lower(substr(u.FName,2)),upper(u.LName),s.name_serv,d.name_dir,c.wifi FROM computers as c, users as u, services as s, directions as d where c.id_user = u.id_user and u.id_serv = s.id_serv and s.id_dir = d.id_dir')
        return render_template('view.html', all=all)
    # or not !
    else:
        return redirect(url_for('login'))

@app.route('/view/<int:entry_id>')
def view_entry(entry_id):
    # am I logged ?
    if 'logged_ro_in' in session or 'logged_rw_in' in session or 'logged_adm_in' in session:
        entry = query_db('SELECT c.id_comp,c.name,c.mac,c.subnet,c.sufix,upper(substr(u.FName,1,1))||lower(substr(u.FName,2)),upper(u.LName),s.name_serv,d.name_dir,c.wifi FROM computers as c, users as u, services as s, directions as d where c.id_user = u.id_user and u.id_serv = s.id_serv and s.id_dir = d.id_dir and c.id_comp = ?', [entry_id], one=True)
        return render_template('view_entry.html', computer=entry)
    # or not !
    else:              
        return redirect(url_for('login'))

#### Read/Write available routes ####

@app.route('/add', methods=['GET','POST'])
def add():
    # am I logged ?
    if 'logged_rw_in' in session or 'logged_adm_in' in session:
        if request.method == 'POST':
            subnet = request.form['subnet'] or 0
            suffix = request.form['suffix'] or 0
            mac = request.form['mac'] or "00:00:00:00:00:00"
            user = request.form['user'] or 1
            name = request.form['name'] or "toto"
            wifi = request.form['wifi'] or 0


            # push query, return result
            new_entry = (
                (subnet, suffix, mac, user, name, wifi)
            )
            result = query_db('INSERT INTO computers(subnet,sufix,mac,id_user,name,wifi) VALUES(?,?,?,?,?,?)', new_entry) 

            # who am I ? (for logging infos)
            if 'logged_rw_in' in session:
                role = 'rw'
            elif 'logged_adm_in' in session:
                role = 'admin'
            else:
                role = 'None'

            # retrieve firstname ans lastname to put in the log entry and format it
            username = query_db('SELECT upper(substr(u.FName,1,1))||lower(substr(u.FName,2)),upper(u.LName) FROM users as u WHERE u.id_user = ?', str(user), one=True) 
            query_info = "10.X." + str(new_entry[0]) + "." + str(new_entry[1]) + " // " + new_entry[2] + " // " + username[0] + " " + username[1] + " // " + new_entry[4] + " // " + str(new_entry[5])

            # build logging infos
            action_user = (
                (request.environ['REMOTE_ADDR'], role, 'ADD', query_info)
            )

            # insert logging infos
            result = query_db('INSERT INTO logs(from_ip,role,action,query) VALUES(?,?,?,?)', action_user)

            # redirect to "view"
            return redirect(url_for('view'))
        else:
            userlist = query_db('SELECT u.id_user,upper(substr(u.FName,1,1))||lower(substr(u.FName,2)),upper(u.LName) FROM users as u')

            # print form
            return render_template('add.html', userlist=userlist)
    # or not !
    else:
        return redirect(url_for('login'))

@app.route('/del/<int:entry_id>', methods=['GET'])
def delete(entry_id):
    # am I logged ?
    if 'logged_rw_in' in session or 'logged_adm_in' in session:

        # Get infos before delete it
        comp = query_db('SELECT c.subnet,c.sufix,upper(substr(u.FName,1,1))||lower(substr(u.FName,2)),upper(u.LName),c.mac,c.name,c.wifi FROM computers as c, users as u where u.id_user = c.id_user and id_comp = ?', [entry_id], one=True)
        # Delete the entry in "computers" table
        result = query_db('DELETE FROM computers WHERE id_comp = ?', [entry_id], one=True)

        # who am I ? (for logging infos)
        if 'logged_rw_in' in session:
            role = 'rw'
        elif 'logged_adm_in' in session:
            role = 'admin'
        else:
            role = 'None'

        query_info = "10.X." + str(comp[0]) + "." + str(comp[1]) + " // " + comp[4] + " // " + comp[2] + " " + comp[3] + " // " + comp[5] + " // " + str(comp[6])
        # build logging infos
        action_user = (
                (request.environ['REMOTE_ADDR'], role, 'DELETE', query_info)
        )

        # insert logging infos
        result = query_db('INSERT INTO logs(from_ip,role,action,query) VALUES(?,?,?,?)', action_user)

        # redirect to "view"
        return redirect(url_for('view'))
    # or not !
    else:
        return redirect(url_for('login'))

#### Admin available routes ####

@app.route('/logs', methods=['GET'])
def logs():
    # am I logged ?
    if 'logged_adm_in' in session:
	limit = request.args.get('limit') or 30
	lines = query_db('select count(*) FROM logs', one=True) or 0

        logs = query_db('select * from logs ORDER BY time DESC LIMIT ?', [limit])
        return render_template('logs.html', logs=logs, lines=lines[0], limit=limit)
    # or not !
    else:              
        return redirect(url_for('login'))

@app.route('/admin')
def admin():
    # am I logged ?
    if 'logged_adm_in' in session:
        return render_template('admin.html')
    # or not !
    else:
        return redirect(url_for('login'))

@app.route('/admin/push', methods=['GET','POST'])
def push():
    # am I logged ?
    if 'logged_adm_in' in session:
        if request.method == 'POST':
            gen_file()

            dom = request.form['dom'] or 'all'
            results = ansible_run('copy', 'src=/tmp/dhcp.out dest=/tmp/dhcp.out owner=root group=root mode=0600', dom)

	    if results is None:
                print "No hosts found"

            results = ansible_run('command', 'sed -i \'s/%%/{{ dom }}/\' /tmp/dhcp.out', dom) 

            if results is None:
                print "No hosts found"

        #for (hostname, result) in results['contacted'].items():
        #    if not 'failed' in result:
        #        print "%s >>> %s" % (hostname, result['stdout'])

        #for (hostname, result) in results['contacted'].items():
        #    if 'failed' in result:
        #       print "%s >>> %s" % (hostname, result['msg'])

        #for (hostname, result) in results['dark'].items():
        #    print "%s >>> %s" % (hostname, result)
	
            return render_template('admin.html', results=results)
        else:
            return render_template('push.html')

    # or not !
    else:
        return redirect(url_for('login'))

@app.route('/admin/status')
def status():
    # am I logged ?
    if 'logged_adm_in' in session:
        results = ansible_run('service', 'name=dhcpd state=started', 'all')

        if results is None:
            print "No hosts found"

        return render_template('admin.html', results=results)
    # or not !
    else:
        return redirect(url_for('login'))

@app.route('/admin/restart', methods=['GET','POST'])
def restart():
    # am I logged ?
    if 'logged_adm_in' in session:
        if request.method == 'POST':
            dom = request.form['dom'] or 'all'

            #results = ansible_run('service', 'name=dhcpd state=started', 'all')
            results = ansible_run('command', 'uptime', dom)

            if results is None:
                print "No hosts found"

            return render_template('admin.html', results=results)
        else:
            return render_template('restart.html')
    # or not !
    else:
        return redirect(url_for('login'))

@app.route('/admin/export', methods=['GET','POST'])
def export():
    # am I logged ?
    if 'logged_adm_in' in session:
        if request.method == 'POST':
            if request.form['export_type'] == "csv":
                # retrieve infos
                results = query_db('SELECT c.id_comp,c.name,c.mac,c.subnet,c.sufix,upper(substr(u.FName,1,1))||lower(substr(u.FName,2)),upper(u.LName),s.name_serv,d.name_dir,c.wifi FROM computers as c, users as u, services as s, directions as d where c.id_user = u.id_user and u.id_serv = s.id_serv and s.id_dir = d.id_dir')

                csv = "ID;Machine;mac;IP;Wifi;Utilisateur;Direction;Service\n"

                for line in results:
                    wifi = "no"
                    if line[9] == 1:
                        wifi = "yes"
                    csv = csv + str(line[0]) + ';' + line[1] + ';' + line[2] + ';' + '10.XX.' + str(line[3]) + '.' + str(line[4]) + ';' + wifi + ';' + line[6] + ' ' + line[5] + ';' + line[7] + ';' + line[8] + "\n" 

                response = make_response(csv)
                response.headers["Content-Disposition"] = "attachment;filename=export.csv"
                return response
            else:
                lease = "# /!\ Exported configuration file /!\ \n# Please modify each \"%%\" occurence by the number of the targeted DOM before use\n\n"
                results = query_db('SELECT c.name,upper(u.LName),upper(substr(u.FName,1,1))||lower(substr(u.FName,2)),c.mac,c.subnet,c.sufix,c.wifi FROM computers as c, users as u where c.id_user = u.id_user')
   
                for line in results:
                    lease = lease + 'Host ' + line[0]
                    if line[6] == 1:
                        lease = lease + '-WIFI'
                    lease = lease + ' { # ' + line[1] + ' ' + line[2] + '\n'
                    lease = lease + '   hardware ethernet ' + line[3] + '; #\n'
                    lease = lease + '   fixed-address 10.%%.' + str(line[4]) + '.' + str(line[5]) + '; #\n'
                    lease = lease + '}\n\n'

                response = make_response(lease)
                response.headers["Content-Disposition"] = "attachment;filename=export.conf"
                return response

            return render_template('admin.html')
        else:
            return render_template('export.html')
    # or not !
    else:
        return redirect(url_for('login'))


######################################

if __name__ == '__main__':
    # No-Prod :
    app.run(debug=True)
    # Prod :
    #app.run(debug=False,host='0.0.0.0')

################ END #################
