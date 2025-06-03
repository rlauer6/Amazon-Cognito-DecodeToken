#!/usr/bin/env perl

package AWS::Cognito::DecodeToken;
# class to verify and decode a JWT token

use strict;
use warnings;

use Carp;
use Crypt::JWT qw(decode_jwt);
use Data::Dumper;
use English qw(-no_match_vars);
use HTTP::Request;
use JSON::MaybeXS;
use Log::Log4perl qw(:easy);
use Log::Log4perl::Level;
use LWP::UserAgent;
use MIME::Base64;
use Pod::Usage;
use Scalar::Util qw(openhandle);
use URI::Escape qw(uri_escape);

use Readonly;

Readonly::Scalar our $ISSUER_BASE       => 'https://cognito-idp.%s.amazonaws.com/%s';
Readonly::Scalar our $JWKS_URL_TEMPLATE => '%s/.well-known/jwks.json';
Readonly::Scalar our $DEFAULT_REGION    => 'us-east-1';

our $VERSION = '0.01';

use parent qw(Class::Accessor::Fast);
__PACKAGE__->follow_best_practice;
__PACKAGE__->mk_accessors(
  qw(
    claims
    client_id
    code
    id_token
    issuer
    jwks_url
    logger
    log_level
    oauth_url
    redirect_uri
    region
    token_file
    user_pool_id
    verify_exp
    decode_only
  )
);

caller or __PACKAGE__->main();

########################################################################
sub new {
########################################################################
  my ( $class, @args ) = @_;

  my $options = ref $args[0] ? $args[0] : {@args};

  $options->{region} //= $DEFAULT_REGION;

  foreach (qw(client_id user_pool_id)) {
    croak "$_ is a required argument\n"
      if !$options->{$_};
  }

  if ( !$options->{token_file} && !$options->{id_token} ) {
    if ( !$options->{code} || !$options->{oauth_url} ) {
      croak
        "either provide a file containing a token (token_file), the token (id_token) or supply the code and the oauth_url\n";
    }
  }

  if ( !$options->{logger} ) {
    $options->{logger} = init_logger($options);
  }

  my $self = $class->SUPER::new($options);

  if ( $self->get_code && $self->get_oauth_url ) {
    $self->fetch_token;
  }
  elsif ( $self->get_token_file ) {
    $self->fetch_token_from_file;
  }

  $self->create_jwks_url;

  return $self;
}

########################################################################
sub init_logger {
########################################################################
  my ($options) = @_;

  $options->{log_level} //= 'info';

  my $level = {
    trace => $TRACE,
    debug => $DEBUG,
    warn  => $WARN,
    info  => $INFO,
  }->{ lc $options->{log_level} };

  $level //= $INFO;

  if ( !Log::Log4perl->initialized ) {
    Log::Log4perl->easy_init($level);
  }

  return Log::Log4perl->get_logger;
}

########################################################################
sub create_jwks_url {
########################################################################
  my ($self) = @_;

  my $region       = $self->get_region;
  my $user_pool_id = $self->get_user_pool_id;

  my $issuer   = sprintf $ISSUER_BASE, $region, $user_pool_id;
  my $jwks_url = sprintf $JWKS_URL_TEMPLATE, $issuer;

  $self->set_jwks_url($jwks_url);
  $self->set_issuer($issuer);

  return $self;
}

########################################################################
sub fetch_token_from_file {
########################################################################
  my ($self) = @_;

  my $file = $self->get_token_file;

  my $fh;

  if ( openhandle $file ) {
    $fh = $file;
  }
  else {
    open $fh, '<', $file
      or croak "could not open $file for reading\n";
  }

  local $RS = undef;

  my $token = decode_json(<$fh>);

  close $fh;

  $self->set_id_token( $token->{id_token} );

  $self->get_logger->debug('successfully fetched token from file');

  return $self;
}

########################################################################
sub decode_claims {
########################################################################
  my ($self) = @_;

  my $id_token = $self->get_id_token;

  my $jwks_url = $self->get_jwks_url;
  my $issuer   = $self->get_issuer;

  # Step 1: Decode header
  my ( $header_b64, undef, undef ) = split /[.]/xsm, $id_token;

  my $header_json = decode_base64url($header_b64);
  my $header      = decode_json($header_json);
  my $kid         = $header->{kid};

  my $ua = LWP::UserAgent->new;

  my $req = HTTP::Request->new( GET => $jwks_url );
  $self->get_logger->debug( Dumper( [ req => $req ] ) );

  # Step 2: Get the JWK set
  my $res = $ua->request($req);
  $self->get_logger->debug( Dumper( [ res => $res ] ) );

  croak 'Failed to fetch JWKS'
    if !$res->is_success;

  my $jwks = decode_json( $res->content );

  # Step 3: Find matching key
  my ($jwk) = grep { $_->{kid} eq $kid } @{ $jwks->{keys} };

  croak sprintf 'No matching key found for kid=%s', $kid
    if !$jwk;

  $self->get_logger->debug( sub { return Dumper( [ jwk => $jwk ] ) } );

  # Step 5: Validate the token
  $self->get_logger->debug(
    sub {
      return Dumper(
        [ decoded => decode_jwt(
            token       => $id_token,
            decode_only => 1,
            key         => $jwk,
            verify_exp  => 0,
          )
        ]
      );
    }
  );

  my $claims = eval {
    return decode_jwt(
      token        => $self->get_id_token,
      key          => $jwk,
      accepted_alg => 'RS256',
      verify_iss   => $issuer,
      verify_exp   => $self->get_verify_exp,
      verify_aud   => $self->get_client_id,
      $self->get_decode_only ? ( decode_only => 1 ) : (),
    );
  };

  croak "JWT validation failed: $EVAL_ERROR"
    if !$claims || $EVAL_ERROR;

  $self->set_claims($claims);

  $self->get_logger->debug( Dumper [ 'successfully decoded claims' => $claims ] );

  return $self;
}

########################################################################
sub decode_base64url {
########################################################################
  my ($str) = @_;

  croak "str is not defined\n"
    if !defined $str;

  $str =~ tr/-_/+/;
  $str .= q{=} while length($str) % 4;

  return MIME::Base64::decode_base64($str);
}

########################################################################
sub fetch_token {
########################################################################
  my ($self) = @_;

  my $ua = LWP::UserAgent->new;

  my %params = (
    grant_type   => 'authorization_code',
    client_id    => $self->get_client_id,
    code         => $self->get_code,
    redirect_uri => $self->get_redirect_uri,
  );

  my $body = join q{&}, map { uri_escape($_) . q{=} . uri_escape( $params{$_} ) } keys %params;

  my $req = HTTP::Request->new(
    POST => $self->get_oauth_url,
    [ 'Content-Type' => 'application/x-www-form-urlencoded' ], $body
  );

  my $rsp = $ua->request($req);

  croak sprintf "Failed to fetch token (%s)\n%s", $rsp->code, $rsp->content
    if !$rsp->is_success;

  my $id_token = eval {
    my $json = decode_json( $rsp->content );
    return $json->{id_token};
  };

  croak sprintf "could not decode content %s\n%s", $rsp->content, $EVAL_ERROR
    if !$id_token || $EVAL_ERROR;

  $self->set_id_token($id_token);

  return $self;
}

########################################################################
sub fetch_config {
########################################################################
  my ($options) = @_;

  local $RS = undef;

  croak sprintf "no such file %s\n", $options->{config}
    if !-e $options->{config};

  open my $fh, '<', $options->{config}
    or croak sprintf "could not open %s for reading\n", $options->{config};

  my $json = decode_json(<$fh>);

  close $fh;

  foreach ( keys %{$json} ) {
    next if exists $options->{$_};
    $options->{$_} = $json->{$_};
  }

  return $options;
}

########################################################################
sub normalize {
########################################################################
  my ($options) = @_;

  foreach my $k ( keys %{$options} ) {
    next if $k !~ /\-/xsm;

    my $v = delete $options->{$k};
    $k =~ s/\-/_/gxsm;
    $options->{$k} = $v;
  }

  return $options;
}

########################################################################
sub main {
########################################################################
  use Getopt::Long qw(:config no_ignore_case);

  my @opt_specs = qw(
    client-id|i=s
    code|c=s
    config|C=s
    help
    log-level=s
    oauth-url=s
    redirect-uri=s
    token-file=s
    user-pool-id=s
    verify-exp
  );

  my %options;

  GetOptions( \%options, @opt_specs );

  if ( $options{help} ) {
    pod2usage( -exitval => 1, -verbose => 1 );
  }

  if ( $options{config} ) {
    fetch_config( \%options );
  }

  $options{'verify-exp'} //= 1;
  $options{'log-level'}  //= 'info';

  normalize( \%options );

  my $claims = AWS::Cognito::DecodeToken->new( \%options )->decode_claims->get_claims;

  print Dumper($claims);

  return 0;
}

1;

__END__

=pod

=head1 NAME

Amazon::Cognito::DecodeToken - decode a JWT token

=head1 SYNOPSIS

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

=head1 DESCRIPTION

Decodes an Amazon Cognito JWT.

=head1 USAGE

 decode-token Options

=head2 Options

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

=head2 Config File

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
 
=head2 Examples

 amazon-cognitor-decode-toke --token-file token.jwt --config tbc-web.json

=head1 METHODS AND SUBROUTINES

=head2 new

Instantiates new C<Amazon::Cognito::DecodeToken> object. Pass a hash
or hash reference of arguments described below.

=over 5

=item code

The code returned upon successful login. If you pass this you must
also pass C<oauth_url>.

You must pass one of C<id_token>, C<token_file>, or C<code>.

=item client_id

=item decode_only

=item id_token

The token string.

You must pass one of C<id_token>, C<token_file>, or C<code>.

=item log_level

=item redirect_uri

The login redirect URI.

Required.

=item oauth_url

Pass this if you pass C<code>.

=item token_file

A file that contains the JSON payload containing the C<id_token> element.

You must pass one of C<id_token>, C<token_file>, or C<code>.

=item user_pool_id

Cognito's user pool id.

Required.

=item verify_exp

Boolean that determines if the expiration date of the token should be verified.

default: true

=back

=head2 decode_claims

Call this after calling the constructor to fetch the token and decode the claims.

=head2 get_claims

Call this after calling C<decode_claims>. Returns a hash ref containing the claims.

=head1 SEE ALSO

L<Crypt::JWT>

=head1 AUTHOR

Rob Lauer - <bigfoot@cpan.org>

=cut
