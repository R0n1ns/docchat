# Generated by Django 5.1.6 on 2025-06-03 15:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("webapp", "0010_remove_pdfsignaturelog_certificate_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="documentversionhistory",
            name="version_url",
            field=models.TextField(null=True),
        ),
    ]
