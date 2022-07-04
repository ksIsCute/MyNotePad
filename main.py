import pymongo
import datetime
import bcrypt
import os
import random
import string
from markupsafe import Markup
from flask_recaptcha import ReCaptcha
from flask import render_template, Flask, request, redirect, make_response
from better_profanity import profanity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
client = pymongo.MongoClient(os.environ['mongo'])
db = client['MainDBs']['Notes']
data = client['MainDBs']['Users']
app = Flask(__name__, '/static')
profanity.load_censor_words()
limit = Limiter(
  app,
  key_func=get_remote_address,
  default_limits=["5 per minute"]
)
recaptcha = ReCaptcha(app=app)

app.config.update(dict(
  RECAPTCHA_ENABLED=True,
  RECAPTCHA_SITE_KEY=os.environ['sit'],
  RECAPTCHA_SECRET_KEY=os.environ['sec']
))

recaptcha = ReCaptcha()
recaptcha.init_app(app)
app.config['SECRET_KEY'] = 'cairocoders-ednalan'

@app.route('/')
def home():
  if request.cookies:
    return render_template("home.html", cookies="true", name=request.cookies.get("x-session-name"))
  return render_template("home.html", cookies="false", name="false")

@app.route("/getuser")
@limit.exempt
def getuser():
  if request.args:
    for i in data.find({"username": request.args.get("username")}):
      return {"code": 200, "notifications": i['notifications']}
  return {"code": 400, "error": "Missing 1 required arg(s)"}

@app.route("/write", methods=["GET", "POST"])
def create():
  notes = 0
  for x in db.find():
    notes += 1
  if request.args:
    err = request.args.get("error")
  else:
    err = ""
  uid = 0
  if request.cookies:
    user = True
  else:
    user = None
  for x in db.find():
    uid += 1
  if request.method == "POST":
    if recaptcha.verify():
      if len(str(request.form.get("title"))) == 0 or len(
        request.form.get("body")) == 0:
          return render_template("write.html", note="Please fill in required forms!", user=user)
      if len(request.form.get("title")) > 35 or len(request.form.get("body")) > 5000:
        return render_template("write.html", note="Please check your title is under 35 characters and your body is under 1000 characters!",user=user)
      if request.form.get("Anonymous") == "on":
        if not profanity.contains_profanity(request.form.get("title")):
          if not profanity.contains_profanity(request.form.get("body")):
            db.insert_one(
              {
                "_id": uid + 1,
                "anonymous": "on",
                "title": request.form.get("title"),
                "note": request.form.get("body"),
                "nsfw": "false",
                "views": 1
              }
            )
          else:
            db.insert_one(
              {
              "_id": uid + 1,
              "anonymous": "on",
              "title": request.form.get("title"),
              "note": request.form.get("body"),
              "nsfw": "true",
              "views": 1
              }
            )
        else:
          db.insert_one(
            {
              "_id": uid + 1,
              "anonymous": "on",
              "title": request.form.get("title"),
              "note": request.form.get("body"),
              "nsfw": "true",
              "views": 1
            }
          )
        return redirect(f"https://MyNotePad.ksiscute.repl.co/view?id={uid + 1}")
      if request.cookies:
        if bcrypt.checkpw(request.cookies.get("x-session-name").encode("UTF8"), request.cookies.get("x-session-token").encode("UTF8")):
          for x in data.find():
            if x['username'].lower() == request.cookies.get("x-session-name").lower():
              try:
                if x['profile']['verified'].lower() == "true":
                  db.insert_one(
                    {
                      "_id": uid + 1,
                      "username": request.cookies.get("x-session-name"),
                      "verified": "true",
                      "title": request.form.get("title"),
                      "note": request.form.get("body"),
                      "nsfw": "false",
                      "views": 1
                    }
                  )
                  return redirect(f"https://MyNotePad.ksiscute.repl.co/view?id={uid + 1}")
              except KeyError:
                db.insert_one(
                  {
                    "_id": uid + 1,
                    "username": request.cookies.get("x-session-name"),
                    "title": request.form.get("title"),
                    "note": request.form.get("body"),
                    "nsfw": "false",
                    "views": 1
                  }
                )
                return redirect(f"https://MyNotePad.ksiscute.repl.co/view?id={uid + 1}")
          else:
            resp = make_response(redirect("https://MyNotePad.ksiscute.repl.co/signup"))
            resp.set_cookie("x-session-name", "", expires=0)
            resp.set_cookie("x-session-token", "", expires=0)
            return resp
          return redirect(f"https://MyNotePad.ksiscute.repl.co/view?id={uid + 1}")
      if not profanity.contains_profanity(request.form.get("title")):
        if not profanity.contains_profanity(request.form.get("body")):
          db.insert_one(
            {
              "_id": uid + 1,
              "title": request.form.get("title"),
              "note": request.form.get("body"),
              "nsfw": "false",
              "views": 1
            }
          )
        else:
          db.insert_one(
            {
            "_id": uid + 1,
            "title": request.form.get("title"),
            "note": request.form.get("body"),
            "nsfw": "true",
            "views": 1
            }
          )
      else:
        db.insert_one(
          {
            "_id": uid + 1,
            "title": request.form.get("title"),
            "note": request.form.get("body"),
            "nsfw": "true",
            "views": 1
          }
        )
      return redirect(f"https://MyNotePad.ksiscute.repl.co/view?id={uid + 1}")
    else:
      return render_template("write.html", note="You need to complete the captcha!", total=uid)
  return render_template("write.html", note=err, total=uid, user=user)

@app.route("/view")
@limit.exempt
def view():
  notes = 0
  for x in db.find():
    notes += 1
  if request.args:
    if request.args.get("error"):
      return render_template("view.html", title="ERROR!", body="This note has been banned or removed from our servers / database! Sorry!", id=0, note=db.find({"_id": "62ae9e6bba2b883251513644"}))
    dbid = request.args.get("id")
    for x in db.find():
      if str(x['_id']) == str(dbid):
        try:
          if x['banned']:
            return redirect("https://MyNotePad.ksiscute.repl.co/view?error=That note is banned or removed!")
        except KeyError:
          try:
            db.update_one(
              {"_id": x['_id']},
              {"$inc": {"views": 1}},
              upsert=True
            )
            return render_template("view.html", title=x['title'], body=x['note'], id=x['_id'], nsfw=x['nsfw'], note=x, total=notes, var=x['views'])
          except BaseException:
            return redirect("https://MyNotePad.ksiscute.repl.co/?error=That form ID doesnt exist!")
    return redirect("https://MyNotePad.ksiscute.repl.co/?error=That form ID doesnt exist!")
  return render_template("notes.html", db=sorted(db.find().sort("views"), key=lambda x: x['views'], reverse=True), count = 0)

@app.route("/stats")
@limit.exempt
def stats():
  nsfw = 0
  sfw = 0
  banned = 0
  notes = 0
  for x in db.find():
    notes += 1
    if x['nsfw'] == "true":
      try:
        if x['banned']:
          banned += 1
          pass
      except KeyError:
        nsfw += 1
    else:
      try:
        if x['banned']:
          banned += 1
          pass
      except KeyError:
        sfw += 1
  return render_template("stats.html", sfw=sfw, nsfw=nsfw, notes=sfw + nsfw, banned=banned, unbanned=notes - banned, total=notes)

# account routes and backend

@app.route("/signup", methods=["GET", "POST"])
def signup():
  if request.method == "POST":
    uid = 1
    for x in data.find():
      uid += 1
    if len(request.form.get("password")) > 50:
      return render_template("accounts/signup.html", error="Your password must be under 50 characters!")
    if len(request.form.get("username")) < 2 or len(request.form.get("username")) > 30:
      return render_template("accounts/signup.html", error="Your username is too long or too short! Please keep it under 30 characters, and at least over 2 characters!")
    for x in data.find():
      if x['username'].lower() == request.form.get("username").lower():
        return render_template("accounts/signup.html", error="That username is taken! Please try another!")
    data.insert_one(
      {
        "_id": uid,
        "username": request.form.get("username"),
        "password": str(bcrypt.hashpw(request.form.get("password").encode(), bcrypt.gensalt()).decode("utf-8")),
        "token": bcrypt.hashpw(request.form.get("username").encode("UTF8"), bcrypt.gensalt()).decode("UTF8"),
        "notifications": [],
        "profile": {
          "status": "None set yet.",
          "bio": "None set yet."
        }
      }
    )
    resp = make_response(render_template("accounts/signup.html", error=f"Logged in as {request.form.get('username')}!"))
    resp.set_cookie('x-session-token', f'{bcrypt.hashpw(request.form.get("username").encode("UTF8"), bcrypt.gensalt()).decode("UTF8")}')
    resp.set_cookie('x-session-name', request.form.get("username"))
    resp.headers['Content-type'] = "text/html"
    return resp
  return render_template("accounts/signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
  resp = make_response(render_template("accounts/login.html", error="Logged in!"))
  if request.method == "POST":
    uid = 1
    for x in data.find():
      uid += 1
      if x['username'] == request.form.get("username"):
        if bcrypt.checkpw(request.form.get("password").encode("UTF8"), x['password'].encode("UTF8")):
          resp.set_cookie('x-session-token', f'{bcrypt.hashpw(request.form.get("username").encode("UTF8"), bcrypt.gensalt()).decode("UTF8")}')
          resp.set_cookie('x-session-name', request.form.get("username"))
          return resp
        return render_template("accounts/login.html", error="Password and/or username is incorrect!")
    return render_template("accounts/login.html", error="That username doesn't exist!")
          
  return render_template("accounts/login.html")

@app.route("/ban")
@limit.exempt
def bannote():
  if request.cookies:
    if bcrypt.checkpw("admin".encode("UTF8"), request.cookies.get("x-session-token").encode("UTF8")) or bcrypt.checkpw("css".encode("UTF8"), request.cookies.get("x-session-token").encode("UTF8")):
      if request.args:
        id = request.args.get("id")
        db.update_one({"_id": int(id)}, {"$set": {"banned": "true"}})
        return render_template("ban.html", db=db.find(), note=f"Note #{id} has been banned!")
      return render_template("ban.html", db=db.find())
    else:
      return redirect("https://MyNotePad.ksiscute.repl.co?error=Only admins can access the ban menu!")
  else:
    return redirect("https://MyNotePad.ksiscute.repl.co/signup")

@app.errorhandler(404)
@limit.exempt
def not_found(e):
    return render_template("404.html")

@app.route("/tos")
def tos():
  notes = 0
  for x in db.find():
    notes += 1
  return render_template("security/tos.html", total=notes)

@app.route("/privacy")
def privacy():
  notes = 0
  for x in db.find():
    notes += 1
  return render_template("security/privacy.html", total=notes)

@app.route("/about")
def about():
  notes = 0
  for x in db.find():
    notes += 1
  return render_template("about.html", total=notes)

@app.route("/profile")
def profile():
  notes = 0
  for x in db.find():
    notes += 1
  if request.args.get("username"):
    for x in data.find():
        if request.args.get("username") == x['username']:
          return render_template("accounts/profile.html", username=x['username'], status=x['profile']['status'], bio=x['profile']['bio'])
  return redirect("https://MyNotePad.ksiscute.repl.co/")

@app.route("/settings", methods=["GET", "POST"])
def settings():
  notes = 0
  for x in db.find():
    notes += 1
  if request.cookies:
    if request.method == "POST":
      if request.form.get("bio"):
        if len(request.form.get("bio")) < 500:
          ubio = request.form.get("bio")
        else:
          return redirect("https://MyNotePad.ksiscute.repl.co/?error=Your bio must be under the 500 character threshold!")
      else:
        ubio = data[request.cookies.get("x-session-name")]['profile']['bio']
      if request.form.get("status"):
        if len(request.form.get("status")) < 100:
          status = request.form.get("status")
        else:
          return redirect("https://MyNotePad.ksiscute.repl.co/?error=Your status must be under the 100 character threshold!")
      else:
        status = data[request.cookies.get("x-session-name")]['profile']['status']
      data.update_one(
        {
          "username": request.cookies.get("x-session-name")
        },
        {
          "$set": {
            "profile": {
              "bio": ubio,
              "status": status
            }
          }
        }
      )
    return render_template("accounts/settings.html", total=notes)
  return redirect("https://MyNotePad.ksiscute.repl.co/?error=Please Login or Sign Up to access the settings menu!")

@app.route("/signout")
def signout():
  if request.cookies:
    resp = make_response(redirect("https://MyNotePad.ksiscute.repl.co/?error=Logged out!"))
    resp.set_cookie("x-session-name", "", expires=0)
    resp.set_cookie("x-session-token", "", expires=0)
    return resp
  return redirect("https://MyNotePad.ksiscute.repl.co/?error=You aren't logged into an account to log out of!")

@app.route("/namechange")
def namechange():
  if request.args.get("newname") and request.args.get("password"):
    if request.cookies:
      for x in data.find():
        if x['username'].lower() == request.cookies.get("x-session-name").lower():
          if bcrypt.checkpw(request.args.get("password").encode("UTF8"), x['password'].encode("UTF8")):
            for i in db.find({"username": {"$exists": "true"}}):
              if i['username'].lower() == x['username'].lower():
                db.update_many(
                  {
                    "username": i['username']
                  },
                  {
                    "$set": {
                      "username": request.args.get("newname")                  
                    }
                  }
                )
                data.update_one(
                  {
                    "username": x['username']
                  },
                  {
                    "$set": {
                      "username": request.args.get("newname")                  
                    }
                  }
                )
                resp = make_response(render_template("nc.html", error="been changed"))
                resp.set_cookie('x-session-token', f'{bcrypt.hashpw(request.args.get("newname").encode("UTF8"), bcrypt.gensalt()).decode("UTF8")}')
                resp.set_cookie('x-session-name', request.args.get("newname"))
                return resp
  return render_template("nc.html", error="not been changed")

app.register_error_handler(400, not_found)
app.run("0.0.0.0", 8080)
