import os, base64, secrets
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, abort, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, String, Integer, Boolean, DateTime, ForeignKey, Text, select, func, desc
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.secret_key = os.environ.get("GAME_SECRET", secrets.token_hex(32))
COMPANY = os.environ.get("GAME_COMPANY", "ByteBop Labs")

# Local: SQLite. Production/Vercel: set DATABASE_URL to a hosted PostgreSQL URL.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///adventure.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # Keep connection pools modest because Vercel may run several function instances.
    engine_kwargs.update({"pool_size": 5, "max_overflow": 10, "pool_timeout": 20})
engine = create_engine(DATABASE_URL, **engine_kwargs)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(24), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    team: Mapped[str] = mapped_column(String(40), default="Solo")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Progress(Base):
    __tablename__ = "progress"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    level: Mapped[int] = mapped_column(Integer)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    score: Mapped[int] = mapped_column(Integer, default=0)
    hints: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Activity(Base):
    __tablename__ = "activity"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(40))
    level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

LEVELS = [
(1,'HTTP vs HTTPS','The Suspicious Envelope','Send one request. Find one weird value. Decode it.','📨',100,'easy'),
(2,'Cookies & Sessions','Who Ate My Cookie?','Bake a harmless cookie and investigate what the browser remembers.','🍪',100,'easy'),
(3,'Authentication','Password, Please!','Figure out what proves who you are without overthinking it.','🪪',125,'easy'),
(4,'Authorization + IDOR','Wrong Locker, Buddy','Two fictional users. One locker. Something is definitely not yours.','🚪',150,'easy'),
(5,'OWASP Top 10','Security Bingo','Match the weird behavior you saw to a security category.','🎯',125,'medium'),
(6,'SQL Injection','The Database Has Opinions','Ask the search box some increasingly suspicious questions.','🗃️',175,'medium'),
(7,'Cross-Site Scripting (XSS)','The Comment Section Strikes Back','Post a harmless test and see what the browser does with it.','💬',175,'medium'),
(8,'Session Security','The Login That Wouldn’t Leave','Investigate session lifetime, logout, and cookie protections.','🎟️',150,'medium'),
(9,'CSRF','Free Pizza, Definitely Real','A request happened. Did the user actually intend it?','🍕',175,'medium'),
(10,'Burp Suite Basics','Request Detective','Intercept one request and become the person who reads before clicking Send.','🕵️',225,'hard')]
FLAGS = {1:'CT{bro_check_the_response}',2:'CT{who_ate_my_cookie}',3:'CT{password_is_not_a_personality}',4:'CT{bro_thats_not_your_profile}',5:'CT{owasp_has_entered_the_chat}',6:'CT{the_database_talked_too_much}',7:'CT{alert_was_not_a_feature}',8:'CT{session_please_behave}',9:'CT{i_didnt_click_that}',10:'CT{intercepted_and_confused}'}
HINTS = {
1:['Click SEND REQUEST, then open DevTools → Network.','Click the request and inspect Response.','That long value is encoded. Try Base64 decoding it.'],
2:['Click BAKE MY COOKIE, then inspect DevTools → Application/Storage → Cookies.','Look at the value of the training cookie.','It is another Base64-style breadcrumb. Decode it.'],
3:['Use the login form and watch Network while signing in.','Look for the request that carries the login attempt.','Ask yourself: what does authentication establish?'],
4:['Open locker 101 first and read the response.','The scenario has exactly two valid lockers.','Compare what happens when the object number changes.'],
5:['Think about the behavior you already experienced.','OWASP categories describe classes of security problems.','Pick the category that best matches the behavior, not the funniest name.'],
6:['Start with a normal search so you know the baseline.','Then try input that tests whether the search treats your text as data or syntax.','Notice how a real database should never let user input rewrite its query.'],
7:['Post a normal comment first.','Try harmless HTML such as bold text and observe how it is rendered.','The lesson is about what the browser interprets, not about attacking anyone.'],
8:['Inspect the session cookie and its attributes.','Test logout and then revisit the protected area.','A good session should have sensible lifetime and protection.'],
9:['Click the pizza button and inspect the request/lesson.','Ask what proves that a state-changing request was intentional.','That missing proof is the heart of CSRF.'],
10:['Intercept one ordinary request in Burp.','Read method, path, headers, parameters and response.','Change only one harmless value, then compare the response.']}
LESSONS = {
1:['HTTP is the language browsers and servers use to communicate.','HTTPS adds TLS protection to HTTP, helping protect data in transit.','DevTools Network shows the request/response conversation.'],
2:['Cookies are small values a browser stores for a site.','HttpOnly helps keep cookies away from JavaScript; Secure restricts them to HTTPS; SameSite helps control cross-site sending.','Never treat client-side values as automatically trustworthy.'],
3:['Authentication asks: “Who are you?”','A login establishes an identity that later requests can associate with a session.','Authorization is a different question: “What are you allowed to do?”'],
4:['Authorization must be checked for the specific object being requested.','If changing an object reference reveals another user’s data, that is an access-control problem commonly called IDOR/BOLA.','The lesson is to verify ownership on the server.'],
5:['OWASP Top 10 is a risk-awareness list for common web application security issues.','Use it as a map for the behaviors you observe, not as a list of magic commands.','Being able to explain the category is more useful than memorizing its number.'],
6:['SQL injection happens when untrusted input changes the meaning of a database query.','Parameterized queries keep data separate from SQL syntax.','The lab is simulated so you can explore the idea safely.'],
7:['XSS happens when untrusted content reaches a browser context where it can be interpreted as code.','Output encoding and appropriate sanitization help prevent it.','Always test only in environments where you have permission.'],
8:['Sessions connect multiple requests to a logged-in identity.','Secure session design includes expiration, invalidation on logout, and appropriate cookie attributes.','Long-lived or poorly protected sessions increase risk.'],
9:['CSRF abuses a browser’s authenticated context to cause an unwanted state-changing action.','Anti-CSRF tokens and appropriate SameSite/CORS/origin controls are common defenses.','The key question is: how does the server verify intent?'],
10:['Burp Suite is a proxy that lets you observe and modify HTTP traffic in an authorized test environment.','Learn the anatomy of a request before learning advanced tooling.','Change one thing at a time and compare results.']}

ADMIN_ACCOUNTS = [
    (os.environ.get("ADMIN1_ID", "admin1"), os.environ.get("ADMIN1_PASSWORD", "")),
    (os.environ.get("ADMIN2_ID", "admin2"), os.environ.get("ADMIN2_PASSWORD", "")),
]
ADMIN_ACCOUNTS = {u:p for u,p in ADMIN_ACCOUNTS if u and p}


def db(): return SessionLocal()
def current_user():
    uid = session.get('uid')
    if not uid: return None
    with db() as s: return s.get(User, uid)

def ensure_progress(s, uid):
    existing = {p.level for p in s.scalars(select(Progress).where(Progress.user_id == uid)).all()}
    for n,*_ in LEVELS:
        if n not in existing: s.add(Progress(user_id=uid, level=n))
    s.commit()

def log(uid, action, level=None, detail=''):
    with db() as s:
        s.add(Activity(user_id=uid, action=action, level=level, detail=detail[:300])); s.commit()

def need(f):
    @wraps(f)
    def w(*a,**k):
        if not current_user(): return redirect(url_for('login'))
        return f(*a,**k)
    return w

def admin_only(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get('admin_id'): abort(404)
        return f(*a,**k)
    return w

def ld(n): return next((x for x in LEVELS if x[0] == n), None)

def player_rows(s):
    rows = []
    users = s.scalars(select(User).order_by(User.created_at)).all()
    for u in users:
        ps = s.scalars(select(Progress).where(Progress.user_id == u.id)).all()
        rows.append({'id':u.id,'username':u.username,'team':u.team,'created':u.created_at,'done':sum(int(p.completed) for p in ps),'score':sum(p.score for p in ps),'hints':sum(p.hints for p in ps)})
    rows.sort(key=lambda x: (-x['score'], -x['done'], x['username'].lower()))
    for i,r in enumerate(rows,1): r['rank']=i
    return rows

@app.context_processor
def ctx(): return {'me':current_user(),'company':COMPANY,'levels':LEVELS}

@app.route('/')
def home(): return redirect(url_for('dashboard') if current_user() else url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        un=request.form.get('username','').strip(); pw=request.form.get('password',''); team=request.form.get('team','').strip() or 'Solo'
        if not 3<=len(un)<=24 or not un.replace('_','').isalnum(): flash('Pick a username with 3–24 letters, numbers or underscores.','error'); return render_template('register.html')
        if len(pw)<6: flash('Use at least 6 characters.','error'); return render_template('register.html')
        if un.lower() in {x.lower() for x in ADMIN_ACCOUNTS}: flash('That username is unavailable. Pick another detective name.','error'); return render_template('register.html')
        with db() as s:
            try:
                u=User(username=un,password_hash=generate_password_hash(pw),team=team); s.add(u); s.commit(); uid=u.id
            except IntegrityError:
                s.rollback(); flash('That detective name is already taken.','error'); return render_template('register.html')
            ensure_progress(s, uid)
        session.clear(); session['uid']=uid; log(uid,'registered'); return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        un=request.form.get('username','').strip(); pw=request.form.get('password','')
        with db() as s: u=s.scalar(select(User).where(User.username==un))
        if u and check_password_hash(u.password_hash,pw):
            session.clear(); session['uid']=u.id; log(u.id,'login'); return redirect(url_for('dashboard'))
        flash('Nope. The keyboard has rejected your credentials.','error')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/dashboard')
@need
def dashboard():
    u=current_user()
    with db() as s:
        ensure_progress(s,u.id)
        ps={p.level:p for p in s.scalars(select(Progress).where(Progress.user_id==u.id)).all()}
        players=player_rows(s); rank=next((r['rank'] for r in players if r['id']==u.id), len(players))
        top=players[:10]
    return render_template('dashboard.html',ps=ps,total=sum(x.score for x in ps.values()),done=sum(x.completed for x in ps.values()),rank=rank,top=top)

@app.route('/level/<int:n>')
@need
def level(n):
    d=ld(n)
    if not d: abort(404)
    u=current_user()
    with db() as s:
        ensure_progress(s,u.id); p=s.scalar(select(Progress).where(Progress.user_id==u.id, Progress.level==n))
    return render_template('level.html',d=d,n=n,p=p,lesson=LESSONS[n],hints=HINTS[n])

@app.route('/api/hint/<int:n>', methods=['POST'])
@need
def hint(n):
    if not ld(n): return jsonify(ok=False),404
    u=current_user()
    with db() as s:
        ensure_progress(s,u.id); p=s.scalar(select(Progress).where(Progress.user_id==u.id, Progress.level==n)); p.hints += 1; s.commit(); num=p.hints
    log(u.id,'hint',n,str(num)); return jsonify(number=num,hint=HINTS[n][min(num-1,len(HINTS[n])-1)])

@app.route('/api/submit', methods=['POST'])
@need
def submit():
    data=request.get_json(silent=True) or request.form
    try: n=int(data.get('level',0))
    except: return jsonify(ok=False,message='Unknown mission.'),400
    if n not in FLAGS: return jsonify(ok=False,message='Unknown mission.'),400
    f=str(data.get('flag','')).strip(); u=current_user()
    with db() as s:
        ensure_progress(s,u.id); p=s.scalar(select(Progress).where(Progress.user_id==u.id, Progress.level==n))
        if p.completed: return jsonify(ok=True,already=True,score=p.score,message='Already solved. Future you is proud of past you.')
        if f==FLAGS[n]:
            base=ld(n)[5]; p.score=max(25,base-max(0,p.hints-2)*25); p.completed=True; s.commit(); score=p.score
        else: score=0
    if score: log(u.id,'flag_correct',n); return jsonify(ok=True,score=score,message='FLAG FOUND. The evidence checks out.')
    log(u.id,'flag_wrong',n); return jsonify(ok=False,message='Not yet. Follow the evidence. The flag is hiding, not teleporting.')

@app.route('/api/leaderboard')
@need
def leaderboard():
    with db() as s: return jsonify(players=player_rows(s)[:25])

@app.route('/lab/mission1/send',methods=['POST'])
@need
def m1():
    encoded=base64.b64encode(FLAGS[1].encode()).decode()
    return jsonify(status='200 OK',message='Support request accepted. Someone definitely left a breadcrumb.',evidence=encoded,encoding='base64')

@app.route('/lab/mission2/bake')
@need
def m2():
    encoded=base64.b64encode(FLAGS[2].encode()).decode()
    resp=make_response(jsonify(message='Cookie delivered. Please do not eat the DevTools.',cookie_name='training_cookie',note='Inspect browser storage.'))
    resp.set_cookie('training_cookie',encoded,httponly=False,secure=request.is_secure,samesite='Lax')
    return resp

@app.route('/lab/mission3/login', methods=['POST'])
@need
def m3():
    return jsonify(
        success=True,
        identity='detective',
        lesson='Authentication established an identity for this session.',
        clue='Identity confirmed. Now ask: what proves who you are?'
    )
@app.route('/lab/mission4/locker/<int:object_id>')
@need
def m4(object_id):
    records={101:{'owner':'alex','item':'Mystery USB','message':'Please return this to Alex.'},202:{'owner':'riley','item':'Pizza voucher','message':'Riley says this is NOT yours.'}}
    rec=records.get(object_id)
    if not rec:return jsonify(error='Locker not found'),404
    return jsonify(locker=object_id,record=rec,lesson='Teaching scenario: the server returned the record because the object ID was accepted. Ask whether ownership was checked.')

@app.route('/lab/mission6/search')
@need
def m6():
    q=request.args.get('q',''); interesting=any(x in q.lower() for x in ["' or ","' or ",'--','union','select'])
    return jsonify(query=q,simulated_result=('Whoa. That input looks like it is trying to become SQL syntax. In a real application, parameterized queries keep it as data.' if interesting else '0 results. Baseline recorded.'),training=True)

@app.route('/lab/mission7/comment',methods=['POST'])
@need
def m7():
    text=request.form.get('text','')
    return jsonify(stored=text,rendered_as_text=True,lesson='Training mode keeps the submission safe. In a real vulnerable renderer, untrusted HTML could become executable browser content.')

@app.route('/lab/mission9/pizza',methods=['POST'])
@need
def m9(): return jsonify(action='pizza_claim',message='Training request received.',lesson='Now inspect the state-changing request and ask what proves the user intended it. That is the CSRF question.')

@app.route('/ops-room-7c4f',methods=['GET','POST'])
def admin_login():
    if request.method=='POST':
        un=request.form.get('username',''); pw=request.form.get('password','')
        if ADMIN_ACCOUNTS.get(un)==pw:
            session.clear(); session['admin_id']=un; return redirect(url_for('admin'))
        flash('Admin credentials rejected.','error')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout(): session.pop('admin_id',None); return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_only
def admin():
    with db() as s:
        users=player_rows(s)
        activity=s.execute(select(Activity,User.username).join(User,User.id==Activity.user_id).order_by(desc(Activity.id)).limit(100)).all()
        mission_stats=[]
        for n,*_ in LEVELS:
            completed=s.scalar(select(func.count()).select_from(Progress).where(Progress.level==n,Progress.completed==True)) or 0
            mission_stats.append({'level':n,'completed':completed})
    return render_template('admin.html',users=users,activity=activity,count=len(users),mission_stats=mission_stats,admin_id=session.get('admin_id'),admins=list(ADMIN_ACCOUNTS.keys()))

@app.route('/admin/reset/<int:uid>',methods=['POST'])
@admin_only
def reset(uid):
    with db() as s:
        s.query(Progress).filter(Progress.user_id==uid).delete(synchronize_session=False); s.commit(); ensure_progress(s,uid)
    flash('Player progress reset.','ok');
    return redirect(url_for('admin'))


@app.get("/loaderio-d5b0667fd9904cf583d29163f99dfaf7.txt")
def loaderio_verification():
    return "loaderio-d5b0667fd9904cf583d29163f99dfaf7", 200, {
        "Content-Type": "text/plain"
    }

if __name__== '__main__':
    print('Web Security Adventure running locally.')
    print('Database:', DATABASE_URL.split('@')[-1])
    print('Admin room: /ops-room-7c4f')
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=False)
