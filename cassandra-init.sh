CQL="CREATE KEYSPACE IF NOT EXISTS ravi_iam WITH replication = {'class': 'SimpleStrategy', 'replication_factor':'1'};
CREATE TABLE easy_iam.authentication (user_name text, user_id text, password text, PRIMARY KEY (user_name));
CREATE TABLE easy_iam.clientConfig (client_id text, client_secret text, scope text, PRIMARY KEY (client_id));
CREATE TABLE easy_iam.authCookie (auth_cookie_id text, isAuthenticated boolean, client_id text, user_name text, user_id text, PRIMARY KEY (auth_cookie_id));
CREATE TABLE easy_iam.authCode (auth_code_id text, user_name text, user_id text, client_id text, scope text, PRIMARY KEY (auth_code_id));
CREATE TABLE easy_iam.token (token_id text, user_name text, user_id text, client_id text, scope text, token text, PRIMARY KEY (token_id));"


until echo $CQL | cqlsh; do
    echo "cqlsh: Cassandra is not available - retry later"
    sleep 2
done &

exec /docker-entrypoint.sh "$@"