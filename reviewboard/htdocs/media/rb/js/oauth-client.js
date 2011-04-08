function access_token_error(jqXHR, textStatus, errorThrown) {
    alert('Status: ' + textStatus + '. Request unsuccessful. (' + errorThrown + ')');
    for (attr in jqXHR)
    {
        alert(attr + ': ' + jqXHR[attr]);
    }
}

function got_access_token(data, textStatus, jqXHR) {
    $('#access_token').val(data.access_token);
    $('#refresh_token').val(data.refresh_token);
}

function get_access_token() {
    // alert('id: ' + $('#client_id').val() + ' secret: ' + $('#client_secret').val() + ' code: ' + $('#code').val());
    $.ajax({
        url: 'http://127.0.0.1:8080/oauth/token/',
        type: 'POST',
        data: {
            'grant_type': 'authorization_code',
            'redirect_uri': 'http://striemer.ca/oauth-client.html',
            'client_id': $('#client_id').val(),
            'client_secret': $('#client_secret').val(),
            'code': $('#code').val()
        },
        success: got_access_token,
        error: access_token_error
    });
}