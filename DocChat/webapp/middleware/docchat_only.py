from django.http import HttpResponseForbidden

class AllowOnlyDocchatApp:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Проверка кастомного User-Agent или заголовка
        if 'DocchatApp' not in user_agent:
            return HttpResponseForbidden("Доступ запрещён")

        return self.get_response(request)
