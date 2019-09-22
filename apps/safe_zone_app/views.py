from django.shortcuts import render, HttpResponse, redirect
import bcrypt
from . models import *

def index(request):
    return render(request, "safe_zone_app/index.html")

def validate(request):
    if 'message' not in request.session:
        request.session['message'] = ""
    try:
        email = request.POST['email']
        user = User.objects.get(email=email) 
        password = request.POST['password']
    except:
        request.session['message'] = "Email not registered!"
        return redirect("/")
        
    return HttpResponse(user.first_name, user.last_name)