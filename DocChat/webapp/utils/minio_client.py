import io
from datetime import timedelta
from minio import Minio
from django.conf import settings
from minio.versioningconfig import VersioningConfig
from webapp.models import Document, DocumentVersionHistory

from DocChat.settings import MINIO_BUCKET_NAME


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

    saved_original_filename = document.original_filename
    data_stream = io.BytesIO(file_content)
    data_length = len(file_content)

    response = client.put_object(
        bucket_name,
        saved_original_filename,
        data_stream,
        data_length,
        content_type=content_type
    )
    version_id = getattr(response, "version_id", None)

    # Генерируем URL для этой версии
    version_url = get_minio_file_url(document, version_id=version_id) if version_id else None

    # Создаем запись в истории версий с URL
    version_history = DocumentVersionHistory.objects.create(
        document=document,
        version_id=str(version_id) if version_id else "unknown",
        file_size=data_length,
        etag=getattr(response, "etag", None),
        notes=notes,
        version_url=version_url  # Сохраняем сгенерированный URL
    )
    return version_history


def download_file_from_minio(document: Document, version_id: str = None):
    """
    Скачивает файл (либо его конкретную версию) из MinIO.

    :param document: Экземпляр модели Document, файл которого требуется скачать.
    :param version_id: (Опционально) Идентификатор конкретной версии файла.
    :return: Объект-ответ от MinIO, поддерживающий метод read() (поток данных).
    """
    client = get_minio_client()
    bucket_name = settings.MINIO_BUCKET_NAME
    # Имя файла берется из поля original_filename документа.
    response = client.get_object(bucket_name, document.original_filename, version_id=version_id)
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


def get_minio_file_url(document: Document, expires=timedelta(hours=1), version_id: str = None):
    client = get_minio_client()
    bucket_name = settings.MINIO_BUCKET_NAME

    try:
        # Убедимся, что version_id - это строка или None
        version_id_str = str(version_id) if version_id else None

        url = client.presigned_get_object(
            bucket_name,
            document.original_filename,
            expires=expires,
            version_id=version_id_str  # Передаем как строку
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
