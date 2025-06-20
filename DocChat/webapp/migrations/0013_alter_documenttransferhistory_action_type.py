# Generated by Django 5.1.6 on 2025-06-10 18:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("webapp", "0012_documentversionhistory_is_signed_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="documenttransferhistory",
            name="action_type",
            field=models.CharField(
                choices=[
                    ("transfer", "Transfer"),
                    ("version_upload", "Version Upload"),
                    ("signature", "Signature"),
                ],
                default="transfer",
                max_length=20,
            ),
        ),
    ]
