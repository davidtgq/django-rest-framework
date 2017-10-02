from django.http import HttpResponse
# from rest_framework.utils import encoders
from django.core.serializers.json import DjangoJSONEncoder

# encoder = encoders.JSONEncoder(ensure_ascii=False, check_circular=False, allow_nan=False, separators=(',', ':'))
encoder = DjangoJSONEncoder(ensure_ascii=False, check_circular=False, allow_nan=False, separators=(',', ':'))


class Response(HttpResponse):
    def __init__(self, data=None, headers=None, *args, **kwargs):
        if data is None:
            super().__init__(bytes(), *args, **kwargs)
        # kwargs.setdefault('Content-Type', 'application/json')
        self['Content-Type'] = "application/json; charset=utf-8"
        if headers:
            for name, value in headers.items():
                self[name] = value
        super().__init__(encoder.encode(data), *args, **kwargs)
