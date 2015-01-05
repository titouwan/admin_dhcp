#!/var/www/dhcp/venv/bin/python
#
# Antoine LOISEAU <a.loiseau@outremer-telecom.fr>
#
# DHCP Admin Application - control and manage OMT dhcp servers
#
# - Records mac and users associated to each computer (sqlite)
# - Generate and send (with ansible) dhcp leases files
#
############# BEGIN ##############

import sqlite3
import ansible.runner
from flask import Flask, render_template, request, session, flash, redirect, url_for, g
app = Flask(__name__)

###### INIT App 
app = Flask(__name__)
app.secret_key = 'A0ZrAdcs&*sc45#$^s6:w32rf3c7$8ew68fwqERGFeRHnbm3(*23bb@#$%'
DATABASE = '/var/lib/sqlite3/dhcp_admin.db'

###### Roles
app.config['USERNAME_ro'] = 'ro'
app.config['PASSWORD_ro'] = 'inf0t3l!'
app.config['USERNAME_rw'] = 'dhcp'
app.config['PASSWORD_rw'] = 'inf0t3l!'
app.config['USERNAME_adm'] = 'admin'
app.config['PASSWORD_adm'] = 'inf0t3l!'

###### Functions

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

############# ROUTES #############

######## Globals (all profiles) ########

@app.route('/')
def home():
    if 'logged_ro_in' in session or 'logged_rw_in' in session or 'logged_adm_in' in session:
        #all = query_db('select c.name,c.mac,c.subnet,c.sufix,u.FName,u.LName,s.name_serv,d.name_dir,c.wifi from computers as c, users as u, services as s, directions as d where c.id_user = u.id_user and u.id_serv = s.id_serv and s.id_dir = d.id_dir')
	all = None
        return render_template('home.html', all=all)
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

#### Read-Only available routes ####

@app.route('/search')
def search():
    if 'logged_ro_in' in session or 'logged_rw_in' in session or 'logged_adm_in' in session:
        return render_template('search.html')
    else:
        return redirect(url_for('login'))

@app.route('/view')
def view():
    if 'logged_ro_in' in session or 'logged_rw_in' in session or 'logged_adm_in' in session:
        all = query_db('SELECT c.id_comp,c.name,c.mac,c.subnet,c.sufix,upper(substr(u.FName,1,1))||lower(substr(u.FName,2)),upper(u.LName),s.name_serv,d.name_dir,c.wifi FROM computers as c, users as u, services as s, directions as d where c.id_user = u.id_user and u.id_serv = s.id_serv and s.id_dir = d.id_dir')
        return render_template('view.html', all=all)
    else:
        return redirect(url_for('login'))

@app.route('/view/<int:entry_id>')
def view_entry(entry_id):
    if 'logged_ro_in' in session or 'logged_rw_in' in session or 'logged_adm_in' in session:
        entry = query_db('SELECT c.id_comp,c.name,c.mac,c.subnet,c.sufix,upper(substr(u.FName,1,1))||lower(substr(u.FName,2)),upper(u.LName),s.name_serv,d.name_dir,c.wifi FROM computers as c, users as u, services as s, directions as d where c.id_user = u.id_user and u.id_serv = s.id_serv and s.id_dir = d.id_dir and c.id_comp = ?', [entry_id], one=True)
        return render_template('view_entry.html', computer=entry)
    else:              
        return redirect(url_for('login'))

#### Read/Write available routes ####

@app.route('/add', methods=['GET','POST'])
def add():
    if 'logged_rw_in' in session or 'logged_adm_in' in session:
        if request.method == 'POST':
            # push query, return result
            #new_entry = (
            #    (request.form['subnet'], request.form['suffix'], request.form['mac'], request.form['name'], request.form['wifi'])
            #)
            new_entry = (
                (200,200,'00:00:00:00:00','toto',1) 
            )
            result = query_db('INSERT INTO computers(subnet,sufix,id_user,mac,name,wifi) VALUES(200,1,1,"00:11:22:33:44:55","paris",0)') 
            return redirect(url_for('view'))
        else:
            # print form
            return render_template('add.html')
    else:
        return redirect(url_for('login'))

#### Admin available routes ####

@app.route('/logs')
def logs():
    if 'logged_adm_in' in session:
        logs = query_db('select * from logs ORDER BY time DESC LIMIT 30;')
        return render_template('logs.html', logs=logs)
    else:              
        return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'logged_adm_in' in session:
        return render_template('admin.html')
    else:
        return redirect(url_for('login'))

@app.route('/admin/push')
def push():
    if 'logged_adm_in' in session:
        results = ansible.runner.Runner(
            pattern='*', forks=10,
            remote_user='root',
            module_name='command', module_args='/usr/bin/uptime', private_key_file='/home/ansible/.ssh/id_dsa',
        ).run()

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
        return redirect(url_for('login'))

@app.route('/admin/restart')
def restart():
    if 'logged_adm_in' in session:
        results = ""
        return render_template('admin.html', results=results)
    else:
        return redirect(url_for('login'))

@app.route('/admin/export')
def export():
    if 'logged_adm_in' in session:
        results = ""
        return render_template('admin.html', results=results)
    else:
        return redirect(url_for('login'))


##################################

if __name__ == '__main__':
    app.run(debug=True)
    #app.run(debug=False,host='0.0.0.0')

############## END ###############
