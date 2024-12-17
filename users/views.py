from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, JsonResponse
from subscriptions.models import UserSubscription
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from django.urls import reverse
import base64
import qrcode
import secrets
import json
from .models import CustomUser, SalesforceConnection, APIKey, LoginHistory, APIUsage, TrustedIP
from io import BytesIO
from django.utils.timezone import now
from datetime import datetime, timedelta
import csv
from decouple import config


SALESFORCE_CLIENT_ID = config('SALESFORCE_CLIENT_ID', default='your-default-secret-key')
SALESFORCE_CLIENT_SECRET = config('SALESFORCE_SECRET', default='your-default-secret-key')
SALESFORCE_CALLBACK_URL = config('SALESFORCE_CALLBACK_URL', default='https://127.0.0.1:8000/users/salesforce/callback/')

@login_required
def disconnect_salesforce_connection(request, connection_id):
    try:
        connection = SalesforceConnection.objects.get(id=connection_id, user=request.user)
        connection.delete()
        return JsonResponse({'success': 'Salesforce connection removed successfully'})
    except SalesforceConnection.DoesNotExist:
        return JsonResponse({'error': 'Connection not found'}, status=404)

@csrf_exempt
@login_required
def save_salesforce_tokens(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        access_token = data.get('access_token')
        instance_url = data.get('instance_url')
        connection_name = request.session.get('connection_name')
        if not access_token or not instance_url or not connection_name:
            return JsonResponse({'error': 'Missing required data'}, status=400)
        SalesforceConnection.objects.create(
            user=request.user,
            connection_name=connection_name,
            access_token=access_token,
            instance_url=instance_url,
            authenticated=True,
        )
        return JsonResponse({'success': 'Salesforce connection added successfully'})

@login_required
def salesforce_login(request):
    connection_name = request.POST.get('connection_name')
    if not connection_name:
        return JsonResponse({'error': 'Connection name is required'}, status=400)
    request.session['connection_name'] = connection_name
    salesforce_auth_url = (
        f"https://login.salesforce.com/services/oauth2/authorize?"
        f"response_type=token&client_id={SALESFORCE_CLIENT_ID}&redirect_uri={SALESFORCE_CALLBACK_URL}"    
    )
    return redirect(salesforce_auth_url)

@login_required
def salesforce_callback(request):
    return render(request, 'users/salesforce_callback.html')

@login_required
def apikeys(request):
    user = request.user
    has_active_subscription = UserSubscription.objects.filter(user=user).exists()
    if not has_active_subscription:
        messages.error(request, "You need an active subscription to manage API keys.")
        return redirect(f"{reverse('profile')}?segment=api-keys")
    production_key = APIKey.objects.filter(user=user, is_production=True).first()
    api_keys = APIKey.objects.filter(user=user, is_production=False)
    api_key_limit_reached = APIKey.objects.filter(user=user).count() >= 5  # Check if limit is reached
    if request.method == "POST" and not api_key_limit_reached:
        try:
            new_api_key = secrets.token_hex(20)
            APIKey.objects.create(user=user, key=new_api_key, is_production=False)
            messages.success(request, "API Key generated successfully.")
            return redirect('apikeys')
        except Exception as e:
            messages.error(request, "An error occurred while generating the API key.")
    return render(request, 'users/apikeys.html', {
        'production_key': production_key,
        'api_keys': api_keys,
        'api_key_limit_reached': api_key_limit_reached,
        'has_active_subscription': has_active_subscription,
        'segment': 'api-keys',
    })



@login_required
def update_api_key(request, key_id):
    user = request.user
    api_key = get_object_or_404(APIKey, id=key_id, user=user)
    if request.method == "POST":
        is_production = request.POST.get("is_production") == "true"
        if is_production:
            APIKey.objects.filter(user=user, is_production=True).update(is_production=False)
        api_key.is_production = is_production
        api_key.save()
        return redirect('apikeys')

@login_required
def delete_api_key(request, key_id):
    user = request.user
    api_key = get_object_or_404(APIKey, id=key_id, user=user)
    if request.method == "POST":
        api_key.delete()
        return redirect('apikeys')

def register(request):
    if request.user.is_authenticated:
        messages.info(request, "You are already logged in.")
        return redirect('profile')
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        confirm_email = request.POST.get('confirm_email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        if email != confirm_email:
            messages.error(request, "Emails do not match.")
            return render(request, 'users/register.html')
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'users/register.html')
        user = CustomUser.objects.create(
            first_name=first_name,
            last_name=last_name,
            email=email,
            username=email
        )
        user.set_password(password)
        user.save()
        messages.success(request, "Account created successfully!")
        return redirect('login') 
    return render(request, 'users/register.html')


def otp_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        otp = request.POST.get('otp', None) 
        try:
            user = CustomUser.objects.get(username=username)
            if not user.check_password(password):
                return render(request, 'users/login.html', {
                    'error': "Invalid username or password.",
                    'otp_required': user.otp_device is not None
                })
            if user.otp_device:
                if not otp or not user.otp_device.verify_token(otp):
                    return render(request, 'users/login.html', {
                        'error': "Invalid OTP. Please try again.",
                        'otp_required': True
                    })
            login(request, user)
            ip_address = get_client_ip(request)
            browser_details = request.META.get('HTTP_USER_AGENT', 'unknown')
            trusted_ip, created = TrustedIP.objects.get_or_create(user=user, ip_address=ip_address)
            if created:
                trusted_ip.is_trusted = False
                trusted_ip.save()
            LoginHistory.objects.create(
                user=user,
                ip_address=ip_address,
                browser_details=browser_details,
                login_time=now()
            )

            return redirect('profile')
        except CustomUser.DoesNotExist:
            return render(request, 'users/login.html', {
                'error': "User does not exist.",
                'otp_required': False
            })
    return render(request, 'users/login.html', {'otp_required': False})

@login_required
def otp_setup(request):
    user = request.user
    device = user.otp_device
    if not device:
        return redirect('profile')
    qr_code = generate_qr_code(device.config_url)
    if request.method == 'POST':
        otp = request.POST.get('otp')
        if device.verify_token(otp):
            messages.success(request, "OTP setup successful!")
            return redirect('profile')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
    return render(request, 'users/otp_setup.html', {'qr_code': qr_code})

def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()

@login_required
def enable_otp(request):
    if request.method == 'POST':
        user = request.user
        if not user.otp_device:
            device = TOTPDevice.objects.create(user=user, name="Default")
            user.otp_device = device
            user.save()
            return redirect('otp_setup')
    return redirect('profile')

@login_required
def disable_otp(request):
    if request.method == 'POST':
        user = request.user
        if user.otp_device:
            user.otp_device.delete()
            user.otp_device = None
            user.save()
            messages.success(request, "OTP has been disabled.")
    return redirect('profile')

@login_required
def profile(request):
    has_active_subscription = UserSubscription.objects.filter(user=request.user, is_active=True).exists()
    api_usage_stats = None
    percentage_change = None
    if has_active_subscription:
        total_calls = APIUsage.objects.filter(user=request.user).count()
        now = datetime.now()
        last_month = now - timedelta(days=30)
        last_month_calls = APIUsage.objects.filter(user=request.user, timestamp__gte=last_month).count()
        previous_month_start = last_month - timedelta(days=30)
        previous_month_calls = APIUsage.objects.filter(user=request.user, timestamp__gte=previous_month_start, timestamp__lt=last_month).count()
        if previous_month_calls > 0:
            percentage_change = ((last_month_calls - previous_month_calls) / previous_month_calls) * 100
        api_usage_stats = {
            'total_calls': total_calls,
            'last_month_calls': last_month_calls,
            'percentage_change': percentage_change,
        }
    return render(request, 'users/profile.html', {
        'segment': 'profile',
        'has_active_subscription': has_active_subscription,
        'api_usage_stats': api_usage_stats,
    })


@login_required
def connections(request):
    user = request.user
    has_active_subscription = UserSubscription.objects.filter(user=user).exists()
    if not has_active_subscription:
        messages.error(request, "You need an active subscription to manage API keys.")
        return redirect(f"{reverse('profile')}?segment=connections")
    return render(request, 'users/connections.html', {
        'segment': 'connections'
    })

def user_logout(request):
    logout(request)
    return redirect('login')

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

@login_required
def profile(request):
    return render(request, 'users/profile.html', {
        'segment': 'profile',
    })

@login_required
def login_history(request):
    one_month_ago = datetime.now() - timedelta(days=30)
    login_history = LoginHistory.objects.filter(user=request.user, login_time__gte=one_month_ago).order_by('-login_time')
    return render(request, 'users/login_history.html', {
        'segment': 'login-history',
        'login_history': login_history,
    })

@login_required
def ip_management(request):
    login_ips = TrustedIP.objects.filter(user=request.user, is_trusted=False)
    trusted_ips = TrustedIP.objects.filter(user=request.user, is_trusted=True)
    return render(request, 'users/ip_management.html', {
        'segment': 'ip_management',
        'login_ips': login_ips,
        'trusted_ips': trusted_ips,
    })

@login_required
def dashbaord(request):
    has_active_subscription = UserSubscription.objects.filter(user=request.user, is_active=True).exists()
    api_usage_stats = None
    percentage_change = None
    if has_active_subscription:
        total_calls = APIUsage.objects.filter(user=request.user).count()
        now = datetime.now()
        last_month = now - timedelta(days=30)
        last_month_calls = APIUsage.objects.filter(user=request.user, timestamp__gte=last_month).count()
        previous_month_start = last_month - timedelta(days=30)
        previous_month_calls = APIUsage.objects.filter(user=request.user, timestamp__gte=previous_month_start, timestamp__lt=last_month).count()
        if previous_month_calls > 0:
            percentage_change = ((last_month_calls - previous_month_calls) / previous_month_calls) * 100
        api_usage_stats = {
            'total_calls': total_calls,
            'last_month_calls': last_month_calls,
            'percentage_change': percentage_change,
        }
    return render(request, 'users/dashboard.html', {
        'segment': 'dashboard',
        'has_active_subscription': has_active_subscription,
        'api_usage_stats': api_usage_stats,
    })

@login_required
def mark_ip_as_trusted(request, ip_id):
    ip = get_object_or_404(TrustedIP, id=ip_id, user=request.user)
    if request.method == "POST":
        ip.is_trusted = True
        ip.save()
        messages.success(request, f"IP {ip.ip_address} has been marked as trusted.")
    return redirect('profile')


@login_required
def delete_ip(request, ip_id):
    ip = get_object_or_404(TrustedIP, id=ip_id, user=request.user)
    if request.method == "POST":
        ip.delete()
        messages.success(request, f"IP {ip.ip_address} has been deleted.")
    return redirect('profile')

@login_required
def download_login_history(request):
    login_history = LoginHistory.objects.filter(user=request.user).order_by('-login_time')
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="login_history.csv"'
    writer = csv.writer(response)
    writer.writerow(['IP Address', 'Browser Details', 'Login Time'])
    for entry in login_history:
        writer.writerow([entry.ip_address, entry.browser_details, entry.login_time])
    return response

@login_required
def update_user_profile(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    if request.method == 'POST':
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.email = request.POST.get('email')
        user._changed_by = request.user
        user.save()
        return redirect('profile')
    

@login_required
def update_profile(request):
    if request.method == 'POST':
        user = request.user
        user.first_name = request.POST.get('first_name', user.first_name)
        user.last_name = request.POST.get('last_name', user.last_name)
        user.save()
        messages.success(request, "Profile updated successfully!")
        return redirect('profile')
    return redirect('profile')