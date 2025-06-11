import io
import urllib
import uuid
from datetime import timedelta, datetime

from django.utils import timezone
from minio import Minio, S3Error
from django.conf import settings
from minio.versioningconfig import VersioningConfig

from DocChat.settings import MINIO_BUCKET_NAME

# Правильный относительный импорт
from ..models import AuditLog, Document, DocumentVersionHistory

def get_minio_client():
    """
    Инициализирует и возвращает экземпляр Minio клиента.
    """
    client = Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE,
    )
    return client


def ensure_bucket_exists(bucket_name: str):
    """
    Проверяет наличие бакета и создает его с включенной версионностью, если он отсутствует.
    """
    client = get_minio_client()
    if not client.bucket_exists(bucket_name):
        client.make_bucket(bucket_name)
        # Включаем версионность для бакета
        versioning_config = VersioningConfig("Enabled")
        client.set_bucket_versioning(bucket_name, versioning_config)



ensure_bucket_exists(MINIO_BUCKET_NAME)


def upload_file_to_minio(document: Document, file_content: bytes, content_type: str, notes: str = None):
    client = get_minio_client()
    bucket_name = settings.MINIO_BUCKET_NAME
    ensure_bucket_exists(bucket_name)

    # Генерируем уникальное имя файла
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved_filename = f"{timestamp}_{document.original_filename}"

    data_stream = io.BytesIO(file_content)
    data_length = len(file_content)

    # Загрузка файла в MinIO
    try:
        response = client.put_object(
            bucket_name,
            saved_filename,  # Используем сгенерированное имя
            data_stream,
            data_length,
            content_type=content_type
        )
    except S3Error as exc:
        print("Error uploading file to MinIO:", exc)
        return None

    version_id = response.version_id if hasattr(response, "version_id") else None

    # Определяем флаги для подписи
    is_signed = notes and "подпис" in notes.lower()
    signature_placeholder = "Подпись заглушка" if is_signed else None

    version_url = client.presigned_get_object(bucket_name, saved_filename, expires=timedelta(hours=1))

    version = DocumentVersionHistory.objects.create(
        document=document,
        version_id=version_id or str(uuid.uuid4()),
        file_name=saved_filename,
        file_size=data_length,
        etag=response.etag,
        timestamp=timezone.now(),
        notes=notes,
        is_signed=is_signed,
        signature_placeholder=signature_placeholder,
        version_url=version_url
    )

    # Логируем действие
    AuditLog.objects.create(
        user=document.owner,
        action="upload_version",
        details=f"Uploaded new version of {document.original_filename} as {saved_filename} (signed: {is_signed})"
    )

    return version


def download_file_from_minio(document: Document, version_id: str = None):
    client = get_minio_client()
    bucket_name = settings.MINIO_BUCKET_NAME

    # Получаем последнюю версию файла из истории
    last_version = document.version_history.order_by('-timestamp').first()
    if not last_version:
        raise FileNotFoundError("No versions available")

    file_name = last_version.file_name  # ✅ используем чистое имя файла

    response = client.get_object(
        bucket_name,
        file_name,
        version_id=version_id
    )
    return response


def delete_file_from_minio(document: Document, version_id: str = None, notes: str = None):
    """
    Удаляет файл (или конкретную версию) из MinIO и сохраняет событие в истории версий.
    Если version_id не указан, функция удаляет все версии файла.

    :param document: Экземпляр модели Document, файл которого требуется удалить.
    :param version_id: (Опционально) Идентификатор версии, которую нужно удалить.
    :param notes: Дополнительное примечание или причина удаления (опционально).
    """
    client = get_minio_client()
    bucket_name = settings.MINIO_BUCKET_NAME

    if version_id is None:
        # # Удаляем все версии файла
        # versions = client.list_objects(bucket_name, prefix=document.filename, recursive=True)
        # for obj in versions:
        #     if obj.object_name == document.filename:
        #
        #         client.remove_object(bucket_name, document.filename, version_id=obj.version_id)
        #         deletion_note = notes or f"Удаление версии {obj.version_id}"
        #         DocumentVersionHistory.objects.create(
        #             document_id=document.id,
        #             version_id=obj.version_id,
        #             file_size=0,
        #             etag="",
        #             notes=deletion_note
        #         )
        # Удаляем конкретную версию
        client.remove_object(bucket_name, document.original_filename)
        deletion_note = notes or f"Удаление файла"
        DocumentVersionHistory.objects.create(
            document_id=document.id,
            version_id="all versions",
            file_size=0,
            etag="",
            notes=deletion_note
        )
    else:
        # Удаляем конкретную версию
        client.remove_object(bucket_name, document.original_filename, version_id=version_id)
        deletion_note = notes or f"Удаление версии {version_id}"
        DocumentVersionHistory.objects.create(
            document_id=document.id,
            version_id=version_id,
            file_size=0,
            etag="",
            notes=deletion_note
        )


def get_minio_file_url(document: Document, expires=timedelta(hours=1)):
    client = get_minio_client()
    bucket_name = settings.MINIO_BUCKET_NAME

    # Получаем последнюю версию документа
    last_version = document.version_history.order_by('-timestamp').first()
    if not last_version:
        return None

    # Используем имя файла из версии
    file_name = last_version.file_name

    try:
        url = client.presigned_get_object(
            bucket_name,
            file_name,
            expires=expires
        )
        return url
    except Exception as e:
        print(f"Ошибка получения ссылки MinIO: {e}")
        return None


def get_file_versions(document: Document):
    """
    Получает историю версий для указанного документа из БД.

    :param document: Экземпляр модели Document, для которого нужно получить историю версий.
    :return: QuerySet записей DocumentVersionHistory для данного документа, отсортированных по убыванию временной метки.
    """
    return document.version_history.all().order_by('-timestamp')
