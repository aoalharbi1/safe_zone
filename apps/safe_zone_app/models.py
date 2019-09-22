from django.db import models

class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField (max_length=225)
    secret_question = models.CharField (max_length=255)
    secret_answer = models.CharField (max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Admin(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField (max_length=25)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Message(models.Model):
    message = models.CharField(max_length=1000)
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False) # False means it has not been read yet
    user = models.ForeignKey(User, related_name="messages")

class Report(models.Model):
    md5 = models.CharField(max_length=32)
    sha1 = models.CharField(max_length=40)
    sha256 = models.CharField(max_length=64)
    checked_at = models.DateTimeField(auto_now_add=True)
    is_safe = models.BooleanField()
    user = models.ForeignKey(User, related_name="reports")

class Company(models.Model):
    name = models.CharField(max_length=255)
    detected = models.BooleanField()
    version = models.CharField(max_length=255)
    result = models.CharField(max_length=255)
    update = models.CharField(max_length=255)
    report = models.ForeignKey(Report, related_name="companies")
