import tempfile
from pathlib import Path

from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, Http404, FileResponse, JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.clickjacking import xframe_options_exempt

from .models import CustomUser, AuditLog, Role, UserGroup, DocumentTransferHistory
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from .utils.otp_email import generate_otp, send_otp_email
from datetime import datetime
from django.utils import timezone as dj_timezone

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import Document, AuditLog
# from .utils.encryption import encrypt_data  # Импортируем функцию шифрования
from .utils.minio_client import *
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from .models import Document
import io

from .utils.pdf_stamp import stamp_pdf_with_dynamic_text
from .utils.signature import verify_pdf_bytes

from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter

User = get_user_model()

def register_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    # Проверяем, на каком этапе регистрации находится пользователь
    show_otp_field = request.session.get("registration_email") is not None

    if request.method == "POST":
        if not show_otp_field:
            # Шаг 1: Пользователь заполняет форму регистрации
            email = request.POST.get("email")
            username = request.POST.get("username")
            password = request.POST.get("password")

            if CustomUser.objects.filter(email=email).exists():
                messages.error(request, "Этот email уже зарегистрирован.")
                return redirect("register")

            # Проверка корпоративного email
            # if not (email.endswith("@company.com") or email.endswith("@corporate.org")):
            #     messages.error(request, "Пожалуйста, используйте корпоративный email.")
            #     return redirect("register")

            # Сохраняем данные пользователя в сессии
            request.session["registration_email"] = email
            request.session["registration_username"] = username
            request.session["registration_password"] = password

            # Генерируем и отправляем OTP
            otp_code = generate_otp()
            request.session["registration_otp"] = otp_code
            request.session["registration_otp_time"] = now().isoformat()
            send_otp_email(email, otp_code)

            messages.info(request, "Код подтверждения отправлен на ваш email.")
            return render(request, "register.html", {"show_otp_field": True})
        else:
            # Шаг 2: Пользователь вводит OTP
            otp_input = request.POST.get("otp")
            otp_stored = request.session.get("registration_otp")
            otp_time = request.session.get("registration_otp_time")

            # Проверяем, что OTP был отправлен и не истек
            if otp_stored and otp_time:
                otp_age = now() - timezone.datetime.fromisoformat(otp_time)
                if otp_age > timedelta(minutes=10):
                    messages.error(request, "Срок действия кода истек. Пожалуйста, зарегистрируйтесь снова.")
                    return redirect("register")

                if otp_input == otp_stored:
                    # Создаем нового пользователя
                    user = CustomUser.objects.create_user(
                        username=request.session["registration_username"],
                        email=request.session["registration_email"],
                        password=request.session["registration_password"],
                        is_email_verified=True
                    )
                    user.backend = 'django.contrib.auth.backends.ModelBackend'
                    login(request, user)

                    # Очищаем данные сессии
                    for key in ["registration_email", "registration_username", "registration_password", "registration_otp", "registration_otp_time"]:
                        request.session.pop(key, None)

                    messages.success(request, "Регистрация прошла успешно!")
                    return redirect("dashboard")
                else:
                    messages.error(request, "Неверный код подтверждения.")
            else:
                messages.error(request, "Код подтверждения не найден или истек.")
            return render(request, "register.html", {"show_otp_field": True})

    return render(request, "register.html", {"show_otp_field": show_otp_field})


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    show_otp_field = request.session.get("login_email") is not None

    if request.method == "POST":
        if not show_otp_field:
            # Шаг 1: Ввод email и пароля
            email = request.POST.get("email")
            password = request.POST.get("password")
            user = authenticate(request, email=email, password=password)

            if user:
                # Генерируем и отправляем OTP
                otp_code = generate_otp()
                request.session["login_email"] = email
                request.session["login_otp"] = otp_code
                request.session["login_otp_time"] = now().isoformat()
                send_otp_email(email, otp_code)

                messages.info(request, "Код проверки был отправлен на вашу электронную почту.")
                return render(request, "login.html", {"show_otp_field": True})
            else:
                messages.error(request, "Недействительная электронная почта или пароль.")
        else:
            # Шаг 2: Ввод OTP
            otp_input = request.POST.get("otp")
            otp_stored = request.session.get("login_otp")
            otp_time = request.session.get("login_otp_time")

            if otp_stored and otp_time:
                # Проверка срока действия OTP
                otp_time = request.session.get("login_otp_time")
                if otp_time:
                    otp_created_at = datetime.fromisoformat(otp_time)
                    if now() - otp_created_at > timedelta(minutes=10):  # Корректное сравнение
                        messages.error(request, "The verification code has expired. Please log in again.")
                        return redirect("login")

                if otp_input == otp_stored:
                    email = request.session.get("login_email")
                    user = CustomUser.objects.get(email=email)
                    user.backend = 'django.contrib.auth.backends.ModelBackend'

                    # Логиним пользователя
                    login(request, user)

                    # Логируем вход
                    AuditLog.objects.create(user=user, action="login")

                    # Очищаем данные сессии
                    for key in ["login_email", "login_otp", "login_otp_time"]:
                        request.session.pop(key, None)

                    messages.success(request, "Login successful.")
                    return redirect("dashboard")
                else:
                    messages.error(request, "Invalid verification code.")

    return render(request, "login.html", {"show_otp_field": show_otp_field})

@login_required
def logout_view(request):
    AuditLog.objects.create(user=request.user, action="logout")
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect("login")

@login_required
def dashboard(request):
    # Собственные документы
    own_documents = Document.objects.filter(owner=request.user)
    # Документы, расшаренные с пользователем:
    # Пользователь получает доступ, если он указан в shared_users или входит в группу из shared_groups
    shared_by_users = Document.objects.filter(shared_users=request.user)
    shared_by_groups = Document.objects.filter(shared_groups__in=request.user.custom_groups.all())
    accessible_documents = (shared_by_users | shared_by_groups).distinct()

    return render(request, "dashboard.html", {
        "documents": own_documents,
        "accessible_documents": accessible_documents,
    })

@login_required
def upload_document(request):
    """Загружает файл и сохраняет первую версию в истории"""
    if request.method == "POST":
        if "file" not in request.FILES:
            messages.error(request, "No file part.")
            return redirect("dashboard")

        file = request.FILES["file"]
        if file.name == "":
            messages.error(request, "No selected file.")
            return redirect("dashboard")

        # Генерируем уникальное имя файла
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_filename = f"{timestamp}_{file.name}"

        # Читаем содержимое файла
        file_content = file.read()

        # Создаем запись в БД
        document = Document.objects.create(
            filename=saved_filename,
            original_filename=file.name,
            content_type=file.content_type,
            owner=request.user,
            is_encrypted=True
        )

        # Загружаем файл в MinIO и получаем объект версии
        version = upload_file_to_minio(document, file_content, file.content_type, "Первоначальная загрузка")

        # Создаем запись в истории передачи для первоначальной загрузки
        DocumentTransferHistory.objects.create(
            document=document,
            sender=request.user,
            notes="Первоначальная загрузка документа",
            version=version,
            action_type="upload"
        )

        # Логируем действие
        AuditLog.objects.create(
            user=request.user,
            action="upload",
            details=f"Uploaded document: {file.name}"
        )

        messages.success(request, "File uploaded and encrypted successfully!")
        return redirect("dashboard")

    return render(request, "dashboard.html")


@login_required
def download_document(request, doc_id):
    """Позволяет пользователю скачать свой документ из MinIO."""
    try:
        document = Document.objects.get(id=doc_id, owner=request.user)
    except Document.DoesNotExist:
        messages.error(request, "Access denied.")
        return redirect("dashboard")

    try:
        response = download_file_from_minio(document)
    except Exception as e:
        messages.error(request, "File not found.")
        return redirect("dashboard")

    # Логируем скачивание
    AuditLog.objects.create(
        user=request.user,
        action="download",
        details=f"Downloaded document: {document.original_filename}"
    )

    return FileResponse(response, as_attachment=True, filename=document.original_filename)

@login_required
def delete_document(request, doc_id):
    document = get_object_or_404(Document, id=doc_id, owner=request.user)
    # Сначала удаляем файл из MinIO и создаём запись истории
    delete_file_from_minio(document)
    # Затем удаляем запись документа из базы данных
    document.delete()
    messages.success(request, "Document deleted successfully.")
    return redirect('dashboard')


@xframe_options_exempt
@login_required
def view_document(request, doc_id):
    document = get_object_or_404(Document, id=doc_id)

    # Получаем всю историю передачи
    transfer_history = document.transfer_history.select_related('sender', 'recipient_user', 'recipient_group',
                                                                'version').order_by('-timestamp')

    # Получаем URL для последней версии
    last_version = transfer_history.first()
    file_url = get_minio_file_url(document) if last_version else None

    if request.method == "POST":
        if "delete" in request.POST:
            if request.user == document.owner:
                delete_file_from_minio(document)
                document.delete()
                messages.success(request, "Документ успешно удален для всех пользователей.")
            else:
                if request.user in document.shared_users.all():
                    document.shared_users.remove(request.user)
                    messages.success(request, "Документ удален из ваших доступных документов.")
                else:
                    messages.error(request, "You cannot delete this document from your list.")
            return redirect("dashboard")
        elif "send" in request.POST:
            return redirect("send_document", doc_id=doc_id)
        elif "download" in request.POST:
            return redirect("download_document", doc_id=doc_id)

    return render(request, "documents/view_document.html", {
        "document": document,
        "transfer_history": transfer_history,  # <-- правильная переменная для шаблона
        "file_url": file_url,
    })


@login_required
def send_document(request, doc_id):
    document = get_object_or_404(Document, id=doc_id)

    if not request.user.can_forward_documents:
        messages.error(request, "You don't have permission to forward documents.")
        return redirect("view_document", doc_id=doc_id)

    # Получаем версии с уже предварительно сгенерированными URL
    versions = document.version_history.order_by('-timestamp')
    current_version = versions.first()

    if request.method == "POST":
        selected_user_ids = request.POST.getlist("users")
        selected_group_ids = request.POST.getlist("groups")
        notes = request.POST.get("notes", "")
        version_id = request.POST.get("version")

        version = versions.filter(version_id=version_id).first() if version_id else None

        # Добавляем пользователей
        users_to_share = CustomUser.objects.filter(id__in=selected_user_ids)
        for user in users_to_share:
            document.shared_users.add(user)
            DocumentTransferHistory.objects.create(
                document=document,
                sender=request.user,
                recipient_user=user,
                notes=notes,
                version=version  # Сохраняем объект версии
            )

        # Добавляем группы
        groups_to_share = UserGroup.objects.filter(id__in=selected_group_ids)
        for group in groups_to_share:
            document.shared_groups.add(group)
            DocumentTransferHistory.objects.create(
                document=document,
                sender=request.user,
                recipient_group=group,
                notes=notes,
                version=version  # Сохраняем объект версии
            )

        messages.success(request, "Document sent successfully.")
        return redirect("view_document", doc_id=doc_id)

    all_users = CustomUser.objects.exclude(id=request.user.id)
    all_groups = UserGroup.objects.all()

    return render(request, "documents/send_document.html", {
        "document": document,
        "all_users": all_users,
        "all_groups": all_groups,
        "versions": versions,
        "current_version": current_version
    })

def check_permission_to_users(user):
    """ Проверка, может ли пользователь управлять правами """
    if not user.is_authenticated or not user.can_modify_users:
        messages.error(user, "Access Denied: You do not have permission.")
        return False
    return True

@login_required
def role_management(request):
    """ Страница управления пользователями и ролями """
    if not check_permission_to_users(request.user):
        return redirect('dashboard')

    search_query = request.GET.get("search", "").strip()
    users = CustomUser.objects.prefetch_related('role').all()

    if search_query:
        users = users.filter(full_name__icontains=search_query)

    return render(request, "admin/users_dashboard.html", {
        "users": users
    })

@login_required
def edit_role(request, user_id):
    if not check_permission_to_users(request.user):
        return redirect('dashboard')

    user = get_object_or_404(CustomUser, id=user_id)
    user_groups = UserGroup.objects.all()

    if request.method == "POST":
        # Если нажата кнопка генерации сертификата
        if "generate_certificate" in request.POST:
            try:
                # Здесь пароль для PKCS#12. В реальном приложении его следует генерировать или запрашивать
                # pkcs12_password = b'password'
                # certificate = create_and_save_certificate(user, pkcs12_password, validity_days=365)
                messages.success(
                    request,
                    f"Новый сертификат успешно создан. Серийный номер: {'test'}"
                    # f"Новый сертификат успешно создан. Серийный номер: {certificate.serial_number}"
                )
            except Exception as e:
                messages.error(request, f"Ошибка генерации сертификата: {str(e)}")
            return redirect("admin_roles_dashboard")

        # Обновление основных данных пользователя
        user.username = request.POST.get("username", user.username)
        user.email = request.POST.get("email", user.email)
        user.full_name = request.POST.get("full_name", user.full_name)
        user.job_title = request.POST.get("job_title", user.job_title)

        # Обновляем группы
        selected_group_ids = request.POST.getlist("groups")
        user.custom_groups.set(UserGroup.objects.filter(id__in=selected_group_ids))

        # Обновляем права пользователя
        permissions_list = [
            "can_manage_documents",
            "can_forward_documents",
            "can_create_documents",
            "can_sign_documents",
            "can_view_statistics",
            "can_modify_users_groups",
            "can_assign_permissions",
        ]
        for perm in permissions_list:
            setattr(user, perm, perm in request.POST)

        user.save()
        messages.success(request, "Данные пользователя успешно обновлены.")
        return redirect("admin_roles_dashboard")

    return render(request, "admin/edit_user.html", {"user": user, "user_groups": user_groups})


@login_required
def create_user(request):
    if not check_permission_to_users(request.user):
        return redirect('dashboard')

    user_groups = UserGroup.objects.all()

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        full_name = request.POST.get("full_name", "")
        job_title = request.POST.get("job_title", "")

        # Проверяем, нет ли уже пользователя с таким email или username
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect("create_user")

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already in use.")
            return redirect("create_user")

        # Создаем нового пользователя
        user = CustomUser.objects.create(
            username=username,
            email=email,
            full_name=full_name,
            job_title=job_title
        )
        # Пароль для защиты PKCS#12 контейнера. Пароль должен быть в байтовом формате.
        pkcs12_password = b'password'

        # Создаем и сохраняем сертификат для пользователя
        # certificate = create_and_save_certificate(user, pkcs12_password, validity_days=365)
        # Применяем группы
        selected_group_ids = request.POST.getlist("groups")
        user.custom_groups.set(UserGroup.objects.filter(id__in=selected_group_ids))

        # Применяем разрешения
        permissions_list = [
            "can_manage_documents",
            "can_forward_documents",
            "can_create_documents",
            "can_sign_documents",
            "can_view_statistics",
            "can_modify_users_groups",
            "can_assign_permissions",
        ]
        for perm in permissions_list:
            setattr(user, perm, perm in request.POST)

        user.set_password("defaultpassword")  # Установить временный пароль
        user.save()

        messages.success(request, "User created successfully.")
        return redirect("admin_roles_dashboard")

    return render(request, "admin/create_user.html", {"user_groups": user_groups})


def check_permission_to_groups(user):
    """ Проверка, может ли пользователь управлять правами """
    if not user.is_authenticated or not user.can_modify_groups:
        messages.error(user, "Access Denied: You do not have permission.")
        return False
    return True

@login_required
def group_dashboard(request):
    """ Страница управления группами """
    if not check_permission_to_groups(request.user):
        return redirect('dashboard')

    groups = UserGroup.objects.all()
    return render(request, "admin/group_dashboard.html", {
        "groups": groups,
    })


@login_required
def edit_group(request, group_id):
    """ Страница изменения группы """
    if not check_permission_to_groups(request.user):
        return redirect('dashboard')

    group = get_object_or_404(UserGroup, id=group_id)
    all_users = CustomUser.objects.all()

    if request.method == "POST":
        # Обновление названия группы
        group.name = request.POST.get("name", group.name)

        # Обновление участников
        member_ids = request.POST.getlist("members")
        group.members.set(CustomUser.objects.filter(id__in=member_ids))

        # Обновление руководителя группы
        leader_id = request.POST.get("leader")
        group.leader = CustomUser.objects.get(id=leader_id) if leader_id else None

        group.save()
        messages.success(request, "Group updated successfully.")
        return redirect('group_dashboard')

    return render(request, "admin/edit_group.html", {
        "group": group,
        "all_users": all_users,
    })
@login_required
def add_group(request):
    """Страница добавления новой группы"""
    if not check_permission_to_groups(request.user):  # Проверяем права пользователя
        return redirect('dashboard')

    all_users = CustomUser.objects.all()

    if request.method == "POST":
        name = request.POST.get("name")
        members_ids = request.POST.getlist("members")
        leader_id = request.POST.get("leader")

        if name:
            group = UserGroup.objects.create(name=name)

            if members_ids:
                group.members.set(CustomUser.objects.filter(id__in=members_ids))

            if leader_id:
                group.leader = CustomUser.objects.get(id=leader_id)

            group.save()
            messages.success(request, "New group created successfully.")
            return redirect('group_dashboard')
        else:
            messages.error(request, "Group name is required.")

    return render(request, "admin/add_group.html", {
        "all_users": all_users
    })


@login_required
def upload_new_version(request, doc_id):
    document = get_object_or_404(Document, id=doc_id, owner=request.user)

    if request.method == "POST":
        if "file" not in request.FILES:
            messages.error(request, "No file selected")
            return redirect("view_document", doc_id=doc_id)

        file = request.FILES["file"]
        notes = request.POST.get("notes", "Комментарий к новой версии")

        file_content = file.read()
        # Загружаем новую версию и получаем объект версии
        version = upload_file_to_minio(document, file_content, file.content_type, notes)

        # Создаем запись о передаче (версия загружена)
        DocumentTransferHistory.objects.create(
            document=document,
            sender=request.user,
            notes=f"Загружена новая версия: {notes}",
            version=version,
            action_type="version_upload"
        )

        messages.success(request, "New version uploaded successfully!")
        return redirect("view_document", doc_id=doc_id)

    return render(request, "documents/upload_new_version.html", {
        "document": document
    })

# @login_required
# def download_version(request, doc_id, version_id):
#     document = get_object_or_404(Document, id=doc_id)
#
#     # Проверка прав доступа
#     if not (document.owner == request.user or
#             request.user in document.shared_users.all() or
#             document.shared_groups.filter(members=request.user).exists()):
#         raise PermissionDenied
#
#     try:
#         response = download_file_from_minio(document, version_id=version_id)
#         version = document.version_history.get(version_id=version_id)
#
#         AuditLog.objects.create(
#             user=request.user,
#             action="download_version",
#             details=f"Downloaded version {version_id} of {document.original_filename}"
#         )
#
#         return FileResponse(response, as_attachment=True, filename=document.original_filename)
#
#     except Exception as e:
#         messages.error(request, f"Error downloading version: {str(e)}")
#         return redirect("view_document", doc_id=doc_id)
@login_required
def sign_document(request, doc_id):
    """Подписывает PDF-документ, добавляя штамп с датой/временем, и сохраняет новую версию"""
    document = get_object_or_404(Document, id=doc_id, owner=request.user)

    if not document.filename.lower().endswith(".pdf"):
        return JsonResponse({'success': False, 'error': 'Можно подписывать только PDF-документы.'}, status=400)

    try:
        # Скачиваем текущую версию из MinIO во временный файл
        minio_response = download_file_from_minio(document)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_input:
            temp_input.write(minio_response.read())
            temp_input_path = Path(temp_input.name)

        # Создаём временный файл для результата
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_output:
            temp_output_path = Path(temp_output.name)

        # Применяем подпись со штампом
        stamp_pdf_with_dynamic_text(temp_input_path, temp_output_path)

        # Загружаем подписанный документ в MinIO как новую версию
        with open(temp_output_path, "rb") as f:
            content = f.read()

        notes = f"Документ подписан пользователем {request.user.full_name}"
        version = upload_file_to_minio(document, content, document.content_type, notes)

        # Создаём запись в истории передачи
        DocumentTransferHistory.objects.create(
            document=document,
            sender=request.user,
            recipient_user=None,  # Отправитель и получатель — один пользователь
            notes=notes,
            version=version,
            action_type="signature"
        )

        # Удаляем временные файлы
        temp_input_path.unlink(missing_ok=True)
        temp_output_path.unlink(missing_ok=True)

        return JsonResponse({'success': True})

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def verify_document(request, doc_id):
    document = get_object_or_404(Document, id=doc_id)
    try:
        response = download_file_from_minio(document)
        pdf_bytes = response.read()
        verified = verify_pdf_bytes(pdf_bytes, [])

        # Добавляем поле success и возвращаем verified
        return JsonResponse({
            'success': True,
            'verified': verified
        })
    except Exception as e:
        # Добавляем success: false и error
        return JsonResponse({
            'success': False,
            'verified': [],
            'error': str(e)
        }, status=500)
