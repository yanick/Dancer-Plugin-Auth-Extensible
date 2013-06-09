use strict;
use warnings;

use lib 't/database';

use Test::More;

use Dancer::Test;

# the dist itself doesn't require the database stuff
eval "use MyApp; 1"
    or plan skip_all => "couldn't load App: $@";

plan tests => 5;

response_status_is '/init' => 200;

response_content_is '/authenticate/max/foo' => 0;
response_content_is '/authenticate/bob/foo' => 0;
response_content_is '/authenticate/bob/please' => 1;

my $resp = dancer_response GET => '/authenticate/bob/please';

response_content_is '/roles' => 'overlord';





