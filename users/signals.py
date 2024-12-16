from django.db.models.signals import pre_save
from django.dispatch import receiver
from .models import CustomUser, UserChangeAudit

@receiver(pre_save, sender=CustomUser)
def track_user_changes(sender, instance, **kwargs):
    if not instance.pk:
        return
    
    previous_user = sender.objects.get(pk=instance.pk)
    
    for field in instance._meta.fields:
        field_name = field.name
        
        if field_name == 'password':
            continue
        
        old_value = getattr(previous_user, field_name)
        new_value = getattr(instance, field_name)
        
        if old_value != new_value:
            UserChangeAudit.objects.create(
                user=instance,
                changed_by=getattr(instance, '_changed_by', None), 
                field_name=field_name,
                old_value=old_value,
                new_value=new_value
            )