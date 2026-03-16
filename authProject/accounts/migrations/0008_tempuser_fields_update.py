# Generated manually

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_userinfo_email_verified_userinfo_mobile_verified_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tempuser',
            name='company',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='tempuser',
            name='job_profile',
            field=models.CharField(max_length=100),
        ),
        migrations.AddField(
            model_name='tempuser',
            name='state',
            field=models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='temp_users', to='accounts.state'),
        ),
        migrations.AddField(
            model_name='tempuser',
            name='city',
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.AddField(
            model_name='tempuser',
            name='password',
            field=models.CharField(default='', max_length=255),
        ),
        migrations.AddField(
            model_name='tempuser',
            name='email_verified',
            field=models.BooleanField(default=False),
        ),
    ]