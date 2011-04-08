from django.http import HttpResponseRedirect, HttpResponse, QueryDict
from django.shortcuts import render_to_response, redirect
from django.template.context import RequestContext
from django.utils import simplejson

from oauth.models import ConsumerApplication, AuthorizationCode, Token
from oauth.decorators import process_oauth_request

@process_oauth_request
def authorize(request, client_id=None, redirect_uri=None,
              state=None, consumer=None, *args, **kwargs):
    """Grant an OAuth authorization request."""
    if request.method == 'POST':
        # A decision was made
        authorize = request.POST.get('authorize', None)
        # I figure this beats throwing 500 errors
        if authorize != 'Authorize' or consumer is None:
            return redirect('oauth.views.invalid_request')
        # Create the authorization code
        authorization_code = consumer.get_authorization_code()
        q = QueryDict('', mutable=True)
        q['code'] = authorization_code.code
        if state is not None:
            q['state'] = state
        return HttpResponseRedirect('%s?%s' % (redirect_uri, q.urlencode()))
    else:
        return render_to_response('oauth/authorize.html',
                RequestContext(request, {'consumer': consumer,
                    'redirect_uri': redirect_uri, 'state': state}))

@process_oauth_request
def token(request, client_id=None, client_secret=None, grant_type=None,
          redirect_uri=None, state=None, consumer=None,
          authorization_code=None, *args, **kwargs):
    """Grant an access token for an authorization code."""
    if request.method == 'POST' and not request.is_secure():
        # I figure this beats throwing 500 errors
        if grant_type != 'authorization_code' or client_secret is None or \
           authorization_code is None or consumer is None:
            return redirect('oauth.views.invalid_request')
        if authorization_code.is_active():
            access_token, refresh_token = \
                    consumer.get_access_and_request_token()
            response = {'access_token': access_token.token, 'expires_in': 3600,
                        'refresh_token': refresh_token.token}
            return HttpResponse(simplejson.dumps(response))
        else:
            return redirect('%s?error=unauthorized_client&state=%s' %
                                                        (redirect_uri, state))
    else:
        return redirect('oauth.views.invalid_request')

def invalid_request(request):
    """Notify the user that there was an invalid OAuth request."""
    return render_to_response('oauth/invalid_request.html',
            RequestContext(request))
