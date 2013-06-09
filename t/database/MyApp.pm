package MyApp;

use Dancer ':syntax';
use Dancer::Plugin::Database;
use Crypt::SaltedHash;

# so that the config takes effect first
BEGIN { 
    set plugins => {
        Database => {
            driver => 'SQLite',
            database => ':memory:',
        },
        'Auth::Extensible' => {
            disable_roles => 0,
            realms => {
                users => {
                    provider => 'Database',
                },
            },
        },
    };

    set session => 'Simple';

    set show_errors => 0;
    #set logger => 'console';
}

use Dancer::Plugin::Auth::Extensible;

my @create_statements = (
    q{
        CREATE TABLE users (
            id       INTEGER     PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(32) NOT NULL       UNIQUE ,
            password VARCHAR(40) NOT NULL
        );
    },
    q{
        CREATE TABLE roles (
            id    INTEGER     PRIMARY KEY AUTOINCREMENT,
            role  VARCHAR(32) NOT NULL
        );
    },
    q{
        CREATE TABLE user_roles (
            user_id  INTEGER  NOT NULL,
            role_id  INTEGER  NOT NULL
        );
    },
);

get '/init' => sub {
    database->do( $_ ) for @create_statements;

    my $sth = database->prepare( 
        q{INSERT INTO users( 'username', 'password' ) VALUES ( ?, ? )} 
    );

    my $csh = Crypt::SaltedHash->new( algorithm => 'SHA-1' );
    $csh->add('please');

    $sth->execute( 'bob', $csh->generate );

    # add a role
    database->do(<<'END_SQL' );
INSERT INTO roles( role ) VALUES ( 'overlord' );
END_SQL

    database->do(<<'END_SQL' );
INSERT INTO user_roles( user_id, role_id ) VALUES ( 
    ( SELECT id FROM users where username = 'bob' ),
    ( SELECT id FROM roles where role = 'overlord' )
);
END_SQL

};

get '/authenticate/:user/:password' => sub {
    my( $success, $realm ) = authenticate_user( ( map { param($_) } qw/ user password / ),
        'users' );

    if( $success ) {
        session logged_in_user => params->{user};
        session logged_in_user_realm => $realm;
    }

    return $success;
};

get '/roles' => sub {
    return join ':', user_roles;
};

1;
