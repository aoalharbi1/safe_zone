from django.shortcuts import render, HttpResponse

def index(request):
    return render(request, "safe_zone_app/index.html")