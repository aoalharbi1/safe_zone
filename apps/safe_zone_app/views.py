from django.shortcuts import render, HttpResponse, redirect
from django.conf import settings
from django.core.files.storage import FileSystemStorage
import bcrypt
from . models import *
import re

# renderes the landing page for both admin/user
def index(request):

    if 'message' not in request.session:
        request.session['message'] = ""

    return render(request, "safe_zone_app/index.html")

# distinguish between user sign in and admin sign in
def validate(request):
    try:
        choice = request.POST['choice']
    except:
        request.session['message'] = "Please pick a choice to sign in as an admin, or a user"
        return redirect("/")

    if choice == "admin":
        try:
            email = request.POST['email']
            admin = Admin.objects.get(email=email)
            form_password = request.POST['password']
            admin_pass = admin.password

            if bcrypt.checkpw(form_password.encode(), admin_pass.encode()):
                request.session['first_name'] = admin.first_name
                request.session['last_name'] = admin.last_name
                request.session['email'] = admin.email
                request.session['admin'] = True
                return redirect("/admin")
            else:
                request.session['message'] = "Check the email and password and try again"
                return redirect("/")
        except:
            request.session['message'] = "Email not registered!"
            return redirect("/")

    elif choice == "user":
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
    else:
        request.session['message'] = "Please pick a choice to sign in as an admin, or a user"
        return redirect("/")

# landing page for user when logged in
def user_in(request):
    if 'email' not in request.session:
        return redirect("/")

    try:
        request.session['admin']
        return redirect("/admin")
    except:   
        email = request.session['email']
        user = User.objects.get(email=email)
        reports = user.reports.all()
        messages = user.messages.all()
        context = {
            'user': user,
            'reports': reports,
            'messages': messages,
        }
        request.session['first_name'] = user.first_name
        request.session['last_name'] = user.last_name
        request.session['email'] = user.email
        request.session['usr_id'] = user.id

        return render(request, "safe_zone_app/user_in.html", context)


def sign_out(request):
    try:
        if 'admin' in request.session:
            del request.session['admin']

        del request.session['message']
        del request.session['email']
        del request.session['first_name']
        del request.session['last_name']
        del request.session['reports']

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


def admin(request):
    if 'email' not in request.session or 'admin' not in request.session:
        return redirect("/")

    if request.session['admin'] != True:
        return redirect("/sign_out")

    context = {
        # all users stores a set of values orderd as bellow,
        "all_users": User.objects.values_list('id', 'first_name', 'last_name', 'email'),
        "all_messages": Message.objects.all(),
    }
    return render(request, 'safe_zone_app/admin_page.html', context)


def show_user_info(request, user_id):
    try:
        if (request.session['admin']):
            context = {
                "all_reports": User.objects.get(id=user_id).reports.all(),
                "user_first_name": User.objects.get(id=user_id).first_name,
                "user_last_name": User.objects.get(id=user_id).last_name,
                "user_email": User.objects.get(id=user_id).email,
                "user_id": user_id
            }
            return render(request, 'safe_zone_app/user_info.html', context)
    except:
        return redirect("/sign_out")


def send_message(request, user_id):
    msgTxt = request.POST['user_message']
    Message.objects.create(message=msgTxt, user=User.objects.get(id=user_id))
    return redirect("/user_in")


def admin_edit_user(request, user_id):
    context = {
        "user_first_name": User.objects.get(id=user_id).first_name,
        "user_last_name": User.objects.get(id=user_id).last_name,
        "user_email": User.objects.get(id=user_id).email,
        "user_id": user_id,
    }
    return render(request, 'safe_zone_app/edit_user_info.html', context)


def edit_info(request, user_id):
    user_to_edit = User.objects.get(id=user_id)
    user_to_edit.first_name = request.POST['first_name']
    user_to_edit.last_name = request.POST['last_name']
    user_to_edit.email = request.POST['email']
    user_to_edit.save()
    return redirect("/admin")


def edit_user(request, user_id):
    if (request.session['usr_id'] == int(user_id)):
        context = {
            "user_first_name": User.objects.get(id=user_id).first_name,
            "user_last_name": User.objects.get(id=user_id).last_name,
            "user_email": User.objects.get(id=user_id).email,
            "user_id": user_id,
        }
        return render(request, 'safe_zone_app/edit_my_profile.html', context)
    return redirect("/sign_out")


def edit_my_profile(request , user_id):
    if request.session['usr_id'] == int(user_id):
        editMyProfile = User.objects.get(id = user_id)
        editMyProfile.first_name = request.POST['first_name']
        editMyProfile.last_name = request.POST['last_name']
        editMyProfile.email = request.POST['email']
        editMyProfile.save()
        return redirect("/user_in")
    return redirect("/sign_out")


def admin_show_report(request, user_id, report_id):
    context = {
        "report": Report.objects.get(id=report_id)
    }
    return render(request, 'safe_zone_app/reports.html', context)

def delete_report(request):
    delete_this = Report.objects.get(id = request.POST['report_id'])
    user_id = request.POST['user_id']
    delete_this.delete()

    return redirect(f"/admin/show_user/{user_id}")

def default_route(request):
    return render(request,"safe_zone_app/404_page.html")

def show_reports(request , report_id):
    if (request.session['usr_id'] == Report.objects.get(id=report_id).user.id):
        context = {
            "report": Report.objects.get(id=report_id)
        }
        return render(request, "safe_zone_app/reports.html", context )
    return redirect("/user_in")

def upload_report (request):
    user_file = request.FILES['file']
    fs = FileSystemStorage(file_permissions_mode=0o600)
    filename = fs.save("./apps/safe_zone_app/static/safe_zone_app/files/" + user_file.name, user_file)
    print(fs.file_permissions_mode)

    # url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    # params = {'apikey': 'ee8638fc597e7441387899153afd8ce11d4352d86e101e0b7cd6b69192dbc9b2'}

    # files = {'file': ('user_file', open('user_file', 'rb'))}

    # response = requests.post(url, files=files, params=params)

    # print(response.json())
    return HttpResponse("Done")
