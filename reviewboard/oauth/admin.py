from django.contrib import admin

from reviewboard.oauth.models import ConsumerApplication, RequestToken, \
                                     AccessToken


class ConsumerApplicationAdmin(admin.ModelAdmin):
    list_display = ('name', 'author', 'authorized', 'public', 'num_requests',
                    'registration_date', 'last_request_date')
    search_fields = ['name', 'author']
    ordering = ['name']

admin.site.register(ConsumerApplication, ConsumerApplicationAdmin)