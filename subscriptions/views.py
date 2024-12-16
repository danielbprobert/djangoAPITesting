from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import SubscriptionOption, UserSubscription
from django.contrib import messages

@login_required
def subscription_options_list(request):
    """
    View to display available subscription options.
    Indicates whether the user is subscribed to each option.
    """
    # Get all subscription options
    subscription_options = SubscriptionOption.objects.all()

    # Get the user's active subscriptions
    user_subscriptions = UserSubscription.objects.filter(user=request.user, is_active=True)

    # Create a map of the user's subscriptions for quick lookup
    user_subscription_map = {sub.subscription_option.id: sub for sub in user_subscriptions}

    # Annotate each subscription option with user's subscription status
    for option in subscription_options:
        option.is_subscribed = option.id in user_subscription_map
        option.is_active_subscription = (
            option.id in user_subscription_map and user_subscription_map[option.id].is_active
        )

    return render(request, 'subscriptions/subscription_options.html', {
        'segment': 'subscriptions',
        'subscription_options': subscription_options,
    })

@login_required
def subscribe(request, option_id):
    """
    View to handle user subscription to a subscription option.
    """
    option = get_object_or_404(SubscriptionOption, id=option_id)
    user = request.user

    # Check if the user already has an active subscription to this option
    existing_subscription = UserSubscription.objects.filter(
        user=user,
        subscription_option=option,
        is_active=True,
    ).first()

    if existing_subscription:
        messages.error(request, "You already have an active subscription to this option.")
        return redirect("subscriptions:subscription_options_list")

    # Create a new subscription
    UserSubscription.objects.create(user=user, subscription_option=option)
    messages.success(request, f"Subscribed to {option.name}!")
    return redirect("subscriptions:subscription_options_list")

@login_required
def profile(request):
    """
    View to display the user's active subscriptions.
    """
    active_subscriptions = UserSubscription.objects.filter(user=request.user, is_active=True)
    return render(request, "subscriptions/profile.html", {"subscriptions": active_subscriptions})