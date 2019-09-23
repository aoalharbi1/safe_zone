from django.shortcuts import render, HttpResponse, redirect
import bcrypt
from . models import *
import re


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
            request.session['first_name'] = user.first_name
            request.session['last_name'] = user.last_name
            request.session['email'] = user.email
            request.session['message'] = ""
            return redirect("/user_in")
        else:
            request.session['message'] = "Check the email and password and try again"
            return redirect("/")
    except:
        request.session['message'] = "Email not registered!"
        return redirect("/")


def user_in(request):
    if 'email' not in request.session:
        return redirect("/")
    return render(request, "safe_zone_app/user_in.html")


def sign_out(request):
    try:
        del request.session['message']
        del request.session['email']
        del request.session['first_name']
        del request.session['last_name']

    except:
        pass
    return redirect("/")


def registration(request):
    names_pattern = re.compile(r'^[a-zA-Z]+$')
    password_pattern = re.compile(
        r'^(?=.*\d)(?=.*[A-Za-z])(?=.*[^\w\d\s:])([^\s]){8,}$')

    if (not names_pattern.match(request.POST['first_name']) or not names_pattern.match(request.POST['last_name'])):
        request.session['message'] = "First name and last name must be alphabetic only"
        return redirect("/")

    if(not password_pattern.match(request.POST['password'])):
        request.session['message'] = "Password must be at least 8 characters, with at least one number and at least on special character"
        return redirect("/")

    hashed_password = bcrypt.hashpw(
        request.POST['password'].encode(), bcrypt.gensalt())
    hashed_answer = bcrypt.hashpw(
        request.POST['secret_answer'].encode(), bcrypt.gensalt())

    request.session['message'] = ""
    new_user = User.objects.create(first_name=request.POST['first_name'],
                                   last_name=request.POST['last_name'],
                                   password=hashed_password,
                                   email=request.POST['email'],
                                   secret_question=request.POST['secret_question'],
                                   secret_answer=hashed_answer)

    return redirect("/")
