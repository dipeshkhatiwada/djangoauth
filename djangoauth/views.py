from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, HttpResponse, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib import messages

def home(request):
    return render(request, 'home.html')

def signup(request):
    if request.method == 'GET':
        return render(request, 'signup.html')
    else:
        u = request.POST.get('username')
        e = request.POST.get('email')
        p1 = request.POST.get('password1')
        p2 = request.POST.get('password2')
        if p1 == p2:
            try:
                u = User(username=u, email=e)
                u.set_password(p1)
                u.save()
            except:
                messages.add_message(request, messages.ERROR, "Username already exists")
                return redirect("signup")
            messages.add_message(request, messages.SUCCESS, "Sign up successfully login to continue")
            return redirect("signin")
        else:
            messages.add_message(request, messages.ERROR, "Password doesn't match")
            return redirect("signup")


def signin(request):
    if request.method == 'GET':
        return render(request, 'signin.html')
    else:
        u = request.POST.get('username')
        # u = request.POST['username']
        p = request.POST.get('password')
        user = authenticate(username=u, password=p)
        if user is not None:
            login(request, user)
            # messages.add_message(request, messages.SUCCESS, "Login success")
            return redirect("dashboard")
        else:
            messages.add_message(request, messages.ERROR, "Username and Password doesn't match")
            return redirect("signin")

        # else:
        #     return HttpResponse("Password Error")


def signout(request):
    logout(request)
    messages.add_message(request, messages.ERROR, "Logout success")
    return redirect('home')


@login_required(login_url='signin')
def dashboard(request):
    context = {
        'blogs': 'sa'
    }
    return render(request, 'dashboard.html', context)

