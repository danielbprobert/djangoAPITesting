import base64
import qrcode
import secrets
import json
import requests
import csv
import hashlib
import os
from sentry_sdk import capture_message, capture_exception
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
from django.conf import settings
from io import BytesIO
from django.utils.timezone import now
from datetime import datetime, timedelta
from decouple import config
from calendar import monthrange
from .models import CustomUser, SalesforceConnection, APIKey, LoginHistory, APIUsage, TrustedIP


def generate_pkce_pair():
    # Generate a random string for the code verifier
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')

    # Create the code challenge by hashing the verifier and encoding it
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).rstrip(b'=').decode('utf-8')

    return code_verifier, code_challenge


@login_required
def disconnect_salesforce_connection(request, connection_id):
    try:
        connection = SalesforceConnection.objects.get(id=connection_id, user=request.user)
        connection.delete()
        return JsonResponse({'success': 'Salesforce connection removed successfully'})
    except SalesforceConnection.DoesNotExist:
        return JsonResponse({'error': 'Connection not found'}, status=404)
    
def get_salesforce_organization_id(access_token, instance_url):
    user_info_url = f"{instance_url}/services/oauth2/userinfo"
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    response = requests.get(user_info_url, headers=headers)
    
    if response.status_code == 200:
        user_info = response.json()
        return user_info.get('organization_id')  # Extract organization ID
    else:
        return None

@login_required
def salesforce_login(request):
    connection_name = request.POST.get('connection_name')
    org_type = request.POST.get('org_type')
    instance_url = request.POST.get('instance_url')
    custom_instance_url = request.POST.get('custom_instance_url')

    if instance_url == 'https://custom.my.salesforce.com' and custom_instance_url:
        instance_url = custom_instance_url

    if not connection_name:
        return JsonResponse({'error': 'Connection name is required'}, status=400)

    if not instance_url:
        return JsonResponse({'error': 'Instance URL is required'}, status=400)

    # Generate PKCE pair
    code_verifier, code_challenge = generate_pkce_pair()

    # Save the code_verifier in the session for later use
    request.session['pkce_code_verifier'] = code_verifier

    salesforce_auth_url = (
        f"{instance_url}/services/oauth2/authorize?"
        f"response_type=code&client_id={settings.SALESFORCE_CLIENT_ID}&redirect_uri={settings.SALESFORCE_CALLBACK_URL}"
        f"&scope=refresh_token+full+openid"
        f"&code_challenge={code_challenge}&code_challenge_method=S256"
    )

    return redirect(salesforce_auth_url)

@login_required
def salesforce_callback(request):
    return render(request, 'connections/salesforce_callback.html')

@login_required
@csrf_exempt
def save_salesforce_tokens(request):
    if request.method != 'POST':
        capture_message("Invalid request method for save_salesforce_tokens", level="warning")
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        # Parse the JSON body
        body = json.loads(request.body)
        access_token = body.get('access_token')
        instance_url = body.get('instance_url')
        refresh_token = body.get('refresh_token')
        
        connection_id = request.session.get('salesforce_connection_id')
        if not connection_id:
            capture_message("Salesforce connection ID is missing in session", level="error")
            return JsonResponse({'error': 'Salesforce connection ID missing in session'}, status=400)

        try:
            salesforce_connection = SalesforceConnection.objects.get(id=connection_id, user=request.user)
        except SalesforceConnection.DoesNotExist:
            capture_exception(Exception(f"SalesforceConnection with ID {connection_id} not found for user {request.user}"))
            return JsonResponse({'error': 'Salesforce connection not found'}, status=404)
        
        organization_id = get_salesforce_organization_id(access_token, instance_url)

        
        salesforce_connection.access_token = access_token
        salesforce_connection.instance_url = instance_url
        salesforce_connection.authenticated = True  
        salesforce_connection.organization_id = organization_id
        salesforce_connection.refresh_token = refresh_token
        salesforce_connection.save()

        return JsonResponse({'message': 'Salesforce connection saved successfully'})
    except Exception as e:
        # Capture the exception and report it to Sentry
        capture_exception(e)
        return JsonResponse({'error': str(e)}, status=500)

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
def add_connection(request):
    return render(request, 'connections/add_connection.html', {
        'segment': 'connections',
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
def connections(request):
    user = request.user
    has_active_subscription = UserSubscription.objects.filter(user=user).exists()
    if not has_active_subscription:
        messages.error(request, "You need an active subscription to manage API keys.")
        return redirect(f"{reverse('profile')}?segment=connections")
    return render(request, 'connections/connections.html', {
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
def dashboard(request):
    has_active_subscription = UserSubscription.objects.filter(user=request.user, is_active=True).exists()
    api_usage_stats = None
    last_20_api_calls = []

    if has_active_subscription:
        # Get subscription limit
        user_subscription = UserSubscription.objects.filter(user=request.user, is_active=True).first()
        user_subscription_limit = user_subscription.subscription_option.api_limit if user_subscription and user_subscription.subscription_option else 0

        # Time calculations
        current_time = now()
        first_day_of_this_month = current_time.replace(day=1)
        first_day_of_last_month = (current_time.replace(day=1) - timedelta(days=1)).replace(day=1)
        last_day_of_last_month = first_day_of_last_month.replace(day=monthrange(first_day_of_last_month.year, first_day_of_last_month.month)[1])

        # Current month API calls
        api_calls_this_month = APIUsage.objects.filter(user=request.user, timestamp__gte=first_day_of_this_month)
        api_calls_this_month_count = api_calls_this_month.count()
        api_calls_this_month_success = api_calls_this_month.filter(process_status='SUCCESS').count()
        api_calls_this_month_error = api_calls_this_month.filter(process_status='FAILURE').count()

        # Last month's API calls
        api_calls_last_month = APIUsage.objects.filter(
            user=request.user,
            timestamp__gte=first_day_of_last_month,
            timestamp__lte=last_day_of_last_month
        )
        last_month_calls_count = api_calls_last_month.count()
        last_month_calls_success = api_calls_last_month.filter(process_status='SUCCESS').count()
        last_month_calls_error = api_calls_last_month.filter(process_status='FAILURE').count()

        # Calculate percentage changes
        percentage_change = (api_calls_this_month_count - last_month_calls_count) / last_month_calls_count * 100 if last_month_calls_count > 0 else 0
        api_calls_success_change = (api_calls_this_month_success - last_month_calls_success) / last_month_calls_success * 100 if last_month_calls_success > 0 else 0
        api_calls_error_change = (api_calls_this_month_error - last_month_calls_error) / last_month_calls_error * 100 if last_month_calls_error > 0 else 0

        # Prepare stats
        api_usage_stats = {
            'api_calls_this_month': api_calls_this_month_count,
            'api_calls_this_month_change_from_last_month': round(percentage_change, 2),
            'api_calls_this_month_success': api_calls_this_month_success,
            'api_calls_this_month_success_change_from_last_month': round(api_calls_success_change, 2),
            'api_calls_this_month_error': api_calls_this_month_error,
            'api_calls_this_month_error_change_from_last_month': round(api_calls_error_change, 2),
            'subscription_limit': user_subscription_limit,
        }

        # Fetch the last 20 API calls
        last_20_api_calls = APIUsage.objects.filter(user=request.user).order_by('-timestamp')[:20]

    return render(request, 'dashboard/dashboard.html', {
        'segment': 'dashboard',
        'has_active_subscription': has_active_subscription,
        'api_usage_stats': api_usage_stats,
        'last_20_api_calls': last_20_api_calls,
    })

@login_required
def transaction_details(request, transaction_id):
    transaction = get_object_or_404(APIUsage, transaction_id=transaction_id, user=request.user)
    process_logs = transaction.process_logs.all().order_by('-start_time')[:10]  # Fetch the last 10 logs

    return render(request, 'dashboard/transaction_details.html', {
        'segment': 'dashboard',
        'transaction': transaction,
        'process_logs': process_logs,  # Pass the limited logs to the template
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