from django.conf.urls.defaults import patterns

urlpatterns = patterns('',
    (r'^authorize/$', 'oauth.views.authorize'),
    (r'^invalid_request/$', 'oauth.views.invalid_request'),
    (r'^token/$', 'oauth.views.token'),
)