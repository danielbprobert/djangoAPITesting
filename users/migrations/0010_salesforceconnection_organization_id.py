# Generated by Django 4.2.17 on 2024-12-17 16:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0009_userchangeaudit'),
    ]

    operations = [
        migrations.AddField(
            model_name='salesforceconnection',
            name='organization_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]