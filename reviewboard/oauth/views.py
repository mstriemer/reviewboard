from django.http import HttpResponseRedirect, HttpResponse, QueryDict
from django.shortcuts import render_to_response
from django.template.context import RequestContext

from oauth.models import ConsumerApplication, AuthorizationCode

# This is an atrocity
def authorize(request):
    """Grant an OAuth authorization request."""
    if request.method == 'POST':
        # A decision was made
        consumer = ConsumerApplication.objects.get(
                    key=request.POST.get('client_id', None))
        # THIS SHOULD BE SAVED SERVER SIDE FOR SECURITY REASONS!
        redirect_uri = request.POST.get('redirect_uri', None)
        if redirect_uri is None:
            return HttpResponseRedirect('/') # Error, what do we do?
        # Create the authorization code
        authorization_code = AuthorizationCode(consumer=consumer, user=request.user)
        authorization_code.full_clean()
        authorization_code.save()
        q = QueryDict('', mutable=True)
        q['code'] = authorization_code.code
        q['state'] = request.POST.get('state', '')
        return HttpResponseRedirect('%s?%s' % (redirect_uri, q.urlencode()))
    else:
        client_id = request.GET.get('client_id', None)
        redirect_uri = request.GET.get('redirect_uri', None)
        state = request.GET.get('state', None)
        if client_id is None:
            # Error
            return HttpResponseRedirect(request.META['HTTP_REFERER'])
        # Ask if they want to authorize
        consumer = ConsumerApplication.objects.get(key=client_id)
        return render_to_response('oauth/authorize.html',
                RequestContext(request, {'consumer': consumer,
                    'redirect_uri': redirect_uri, 'state': state}))
