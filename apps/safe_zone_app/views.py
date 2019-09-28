from django.shortcuts import render, HttpResponse, redirect
from django.conf import settings
from django.core.files.storage import FileSystemStorage
import bcrypt
import re
import requests
from time import sleep
from . models import *

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
            request.session['message'] = "Check the email and password and try again"
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
            request.session['message'] = "Check the email and password and try again"
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
        reports = user.reports.all().order_by("-id")
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

        if 'usr_id' in request.session:
            del request.session['usr_id']

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
                "all_reports": User.objects.get(id=user_id).reports.all().order_by("-id"),
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


def edit_my_profile(request, user_id):
    if request.session['usr_id'] == int(user_id):
        editMyProfile = User.objects.get(id=user_id)
        editMyProfile.first_name = request.POST['first_name']
        editMyProfile.last_name = request.POST['last_name']
        editMyProfile.email = request.POST['email']
        editMyProfile.save()
        return redirect("/user_in")
    return redirect("/sign_out")


def admin_show_report(request, user_id, report_id):
    report = Report.objects.get(id=report_id)
    context = {
        "report": report,
        "companies": report.companies.all().order_by("name").values()
    }
    return render(request, 'safe_zone_app/reports.html', context)


def delete_report(request):
    delete_this = Report.objects.get(id=request.POST['report_id'])
    user_id = request.POST['user_id']
    delete_this.delete()

    if 'admin' in request.session:
        return redirect(f"/admin/show_user/{user_id}")

    return redirect("/user_in")


def show_reports(request, report_id):
    if (request.session['usr_id'] == Report.objects.get(id=report_id).user.id):
        report = Report.objects.get(id=report_id)
        context = {
            "report": report,
            "companies": report.companies.all().order_by("name").values()
        }
        return render(request, "safe_zone_app/reports.html", context)
    return redirect("/user_in")


# 	The purpose of the function: Takes a file and sends it to the external API, it will keep checking until the file has been checked
# 	What are the parameters: None
#	return: a json object containing information about the file
def upload_report(request):
    if request.method == 'POST' and request.FILES['file']:

        user_file = request.FILES['file']

        # setting the directory and the file permissions to read only
        fs = FileSystemStorage(directory_permissions_mode=0o400,
                               file_permissions_mode=0o400)
        filename = fs.save(
            "./apps/safe_zone_app/static/safe_zone_app/files/" + user_file.name, user_file
        )

        # Calling the external API
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {
            'apikey': 'ee8638fc597e7441387899153afd8ce11d4352d86e101e0b7cd6b69192dbc9b2'}

        files = {'file': (filename, open(filename, 'rb'))}

        response = requests.post(url, files=files, params=params)
        # End of the call

        # Delete the uploaded file from the server
        fs.delete(filename)

        file_hash = response.json()['sha256']

        # This loop will keep checking with the API (every minute) to see if the file has been scanned yet
        while(True):
            api_report = scan(file_hash)

            if api_report['response_code'] != -2:
                break

            sleep(40)

        if 'email' not in request.session:
            request.session['result'] = api_report
            return redirect("/show_report_not_signed_in")

        else:
            insert_report(request, api_report)

        return HttpResponse(True)

    return HttpResponse(False)

# 	The purpose of the function: Sends the hash of the file to external APIs
# 	What are the parameters: the sha256 hash of the file
#	return: a json object containing information about the file


def scan(hash):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {
        'apikey': 'ee8638fc597e7441387899153afd8ce11d4352d86e101e0b7cd6b69192dbc9b2',
        'resource': hash
    }

    response = requests.get(url, params=params)

    return response.json()


def insert_report(request, result):
    if 'email' not in request.session:
        return redirect("/sign_out")

    user = User.objects.get(email=request.session['email'])

    if result['positives'] > 0:
        is_safe = False
    else:
        is_safe = True

    report = Report.objects.create(
        md5=result['md5'], sha1=result['sha1'], sha256=result['sha256'], is_safe=is_safe, user=user)

    for company, info in result['scans'].items():
        Company.objects.create(name=company, detected=info['detected'], version=info['version'], result=str(
            info['result']), update=info['update'], report=report)

    return


def show_report_not_signed_in(request):
    api_report = request.session['result']

    context = {
        "companies": api_report.pop('scans'),
        "report": api_report
    }
    return render(request, "safe_zone_app/show_report_not_signed_in.html", context)


def default_route(request):
    return render(request, "safe_zone_app/404_page.html")
