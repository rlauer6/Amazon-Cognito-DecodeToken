# NAME

Amazon::Cognito::DecodeToken - decode a JWT token

# SYNOPSIS

    my $claims = Amazon::Cognito::DecodeToken->new(
      id_token     => $id_token,
      client_id    => $client_id,
      user_pool_id => $user_pool_id,
      redirect_uri => $redirect_uri,
    )->decode_claims->get_claims;

or

    my $claims = Amazon::Cognito::DecodeToken->new(
      code         => $code,
      client_id    => $client_id,
      user_pool_id => $user_pool_id,
      redirect_uri => $redirect_uri,
      oauth_url    => 'https://treasurersbriefcase.auth.us-east-1.amazoncognito.com/oauth2/token',
    )->decode_claims->get_claims;

# DESCRIPTION

Decodes an Amazon Cognito JWT.

# USAGE

    decode-token Options

## Options

    --client-id|i        client id
    --code|c             code returned from successful login
    --config|C           config file (JSON format)
    --help               this
    --log-level          logging level (trace, debug, info, warn, error)
    --oauth-url          authorization URL
    --redirect-uri       redirect uri
    --token-file         file with the JSON payload containing the id_token element
    --user-pool-id       Cognitor user pool id
    --verify-exp         Boolean that indicates if expiration of token should be checked

## Config File

The config file should be a JSON file that contains options that will
be used if present. Command line options override options in the
config file.

    {
     "client-id"    : "36cpai7at2snxj3v2fl80zkprh",
     "user-pool-id" : "us-east-1_WLHU6ewKz",
     "redirect-uri" : "https://myapp.com/login",
     "oauth-url"    : "https://treasurersbriefcase.auth.us-east-1.amazoncognito.com/oauth2/token",
     "log-level"    : "debug"
    }
    

## Examples

    amazon-cognitor-decode-toke --token-file token.jwt --config tbc-web.json

# METHODS AND SUBROUTINES

## new

Instantiates new `Amazon::Cognito::DecodeToken` object. Pass a hash
or hash reference of arguments described below.

- code

    The code returned upon successful login. If you pass this you must
    also pass `oauth_url`.

    You must pass one of `id_token`, `token_file`, or `code`.

- client\_id
- decode\_only
- id\_token

    The token string.

    You must pass one of `id_token`, `token_file`, or `code`.

- log\_level
- redirect\_uri

    The login redirect URI.

    Required.

- oauth\_url

    Pass this if you pass `code`.

- token\_file

    A file that contains the JSON payload containing the `id_token` element.

    You must pass one of `id_token`, `token_file`, or `code`.

- user\_pool\_id

    Cognito's user pool id.

    Required.

- verify\_exp

    Boolean that determines if the expiration date of the token should be verified.

    default: true

## decode\_claims

Call this after calling the constructor to fetch the token and decode the claims.

## get\_claims

Call this after calling `decode_claims`. Returns a hash ref containing the claims.

# SEE ALSO

[Crypt::JWT](https://metacpan.org/pod/Crypt%3A%3AJWT)

# AUTHOR

Rob Lauer - <bigfoot@cpan.org>
