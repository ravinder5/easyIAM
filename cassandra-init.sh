CQL="CREATE KEYSPACE IF NOT EXISTS easy_iam WITH replication = {'class': 'SimpleStrategy', 'replication_factor':'1'};
CREATE TABLE easy_iam.authentication (user_name text, user_id text, password text, PRIMARY KEY (user_name));
CREATE TABLE easy_iam.clientConfig (client_id text, client_secret text, scope text, grant_types list<text>, PRIMARY KEY (client_id));
CREATE TABLE easy_iam.authCookie (auth_cookie_id text, isAuthenticated boolean, client_id text, user_name text, user_id text, PRIMARY KEY (auth_cookie_id));
CREATE TABLE easy_iam.authCode (auth_code_id text, user_name text, user_id text, client_id text, scope text, PRIMARY KEY (auth_code_id));
CREATE TABLE easy_iam.tokenById(token_id text, user_name text, user_id text, client_id text, scope text, access_token text, PRIMARY KEY (token_id));
INSERT INTO easy_iam.authentication(user_name,user_id,password) VALUES ('test@test.com','12345','password');
INSERT INTO easy_iam.clientConfig(client_id,client_secret,scope,grant_types) VALUES ('test-1.0.0','password','iam.admin',['authorization_code', 'refresh_token']);"


until echo $CQL | cqlsh; do
    echo "cqlsh: Cassandra is not available - retry later"
    sleep 2
done &

exec /docker-entrypoint.sh "$@"