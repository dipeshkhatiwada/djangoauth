from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages

def home(request):
    if request.user.id:
        return redirect('dashboard')
    return render(request, 'home.html')

def signup(request):
    if request.user.id:
        return redirect('dashboard')
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
    if request.user.id:
        return redirect('dashboard')
    if request.method == 'GET':
        return render(request, 'signin.html')
    else:
        u = request.POST.get('username')
        # u = request.POST['username']
        p = request.POST.get('password')
        user = authenticate(username=u, password=p)
        if user is not None:
            login(request, user)
            messages.add_message(request, messages.SUCCESS, "Login success")
            return redirect("dashboard")
        else:
            messages.add_message(request, messages.ERROR, "Username and Password doesn't match")
            return redirect("signin")


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

@login_required(login_url='signin')
def change_password(request):
    if request.method == 'GET':
        form = PasswordChangeForm(request.user)
        context = {'forms': form}
        return render(request, 'change_password.html', context)
    else:
        form = PasswordChangeForm(request.user, request.POST)
        if request.POST.get('new_password1') == request.POST.get('new_password2'):
            if form.is_valid():
                user = form.save()
                update_session_auth_hash(request, user)  # Important!
                messages.add_message(request, messages.SUCCESS, "Your password is successfully updated!")
                return redirect('change_password')
            else:
                messages.add_message(request, messages.ERROR, "Password doesn't match")
                return redirect('change_password')

        else:
            messages.add_message(request, messages.ERROR, "Password and Confirm doesn't match")
            return redirect('change_password')

        # old_pass = request.POST.get('old_password')
        # new_pass1 = request.POST.get('password1')
        # new_pass2 = request.POST.get('password2')
        # # u = request.POST['username']
        # user = authenticate(username=request.user.username, password=old_pass)
        # if user is not None:
        #     if new_pass1 == new_pass2:
        #         user = User.objects.get(id=request.user.id)
        #         print(user)
        #         user.set_password(new_pass1)
        #         messages.add_message(request, messages.SUCCESS, "Password Changed Successfully")
        #         return redirect("dashboard")
        #     else:
        #         messages.add_message(request, messages.ERROR, "Password and Confirm doesn't match")
        #         return redirect("change_password")
        # else:
        #     messages.add_message(request, messages.ERROR, "Old password doesn't match")
        #     return redirect("change_password")
