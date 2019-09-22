from django.shortcuts import render, HttpResponse, redirect
import bcrypt
from . models import *

def index(request):
    if 'message' not in request.session:
        request.session['message'] = ""

    return render(request, "safe_zone_app/index.html")

def validate(request):
    try:
        email = request.POST['email']
        user = User.objects.get(email=email) 
        form_password = request.POST['password']
        user_pass = user.password

        if bcrypt.checkpw(form_password.encode(), user_pass.encode()):
            request.session['user_first_name'] = user.first_name
            request.session['user_last_name'] = user.last_name
            request.session['user_email'] = user.email
            return redirect ("/user_in")
        else:
            request.session['message'] = "Check the email and password and try again"
            return redirect("/")
    except:
        request.session['message'] = "Email not registered!"
        return redirect("/")