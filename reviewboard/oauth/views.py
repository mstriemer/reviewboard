from django.http import HttpResponseRedirect, HttpResponse, \
                        HttpResponseForbidden, QueryDict
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
        if consumer is None:
            return redirect('oauth.views.invalid_request')
        if authorize != 'Authorize':
            return redirect('%s?%s' % (consumer.redirect_uri, 'error='))
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
            response = QueryDict('', mutable=True)
            response['access_token'] = access_token.token
            # response['expires_in'] = 3600
            response['refresh_token'] = refresh_token.token
            return HttpResponse(response.urlencode())
        else:
            return redirect('%s?error=unauthorized_client&state=%s' %
                                                        (redirect_uri, state))
    else:
        return redirect('oauth.views.invalid_request')

def invalid_request(request):
    """Notify the user that there was an invalid OAuth request."""
    return render_to_response('oauth/invalid_request.html',
            RequestContext(request))

def protected(request):
    """A 'protected' resource."""
    token = request.REQUEST.get('token', None)
    if token is None:
        return HttpResponseForbidden('You are not authorized to access this resource (no token provided)')
    try:
        access_token = Token.objects.get(token=token, token_type='access')
    except Token.DoesNotExist:
        return HttpResponseForbidden('You are not authorized to access this resource (token does not exist)')
    if access_token.is_active():
        return HttpResponse('The protected resource is: "(ReviewBoard + OAuth-2.0) / 2.0 = 2:47AM"')
    else:
        return HttpResponseForbidden('You are not authrized to access this resource (token is no longer active)')
