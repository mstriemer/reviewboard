from django.shortcuts import redirect
from oauth.models import ConsumerApplication, AuthorizationCode

def process_oauth_request(fn):
    """Process and OAuth request and return the consumer or an error."""
    def inner(request, *args, **kwargs):
        oauth = {}
        oauth['client_id'] = request.REQUEST.get('client_id', None)
        oauth['client_secret'] = request.REQUEST.get('client_secret', None)
        oauth['redirect_uri'] = request.REQUEST.get('redirect_uri', None)
        oauth['state'] = request.REQUEST.get('state', None)
        oauth['code'] = request.REQUEST.get('code', None)
        oauth['grant_type'] = request.REQUEST.get('grant_type', None)
        try:
            consumer_args = {'key': oauth['client_id'], 'user': request.user}
            if oauth['client_secret'] is not None:
                consumer_args.update({'secret': oauth['client_secret']})
            oauth['consumer'] = ConsumerApplication.objects.get(**consumer_args)
            if oauth['code'] is not None:
                oauth['authorization_code'] = AuthorizationCode.objects.get(
                    consumer=oauth['consumer'], user=request.user,
                    code=oauth['code'], authorized=True)
        except ConsumerApplication.DoesNotExist:
            raise RuntimeError, '%r' % oauth
            return redirect('oauth.views.invalid_request')
        if oauth['redirect_uri'] != oauth['consumer'].redirect_uri:
            raise RuntimeError, 'redirect_uri'
            return redirect('oauth.views.invalid_request')
        kwargs.update(oauth)
        return fn(request, *args, **kwargs)
    return inner
