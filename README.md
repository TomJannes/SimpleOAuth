Openid connect example
----------------------

Configuration
-------------
config can be found in the config folder.
set environment by calling export NODE_ENV=<environment>

mongodb
-------
mongodb migrations will be used to perform data seed (https://github.com/emirotin/mongodb-migrations)
create migration: ./node_modules/.bin/mm create newfile --config=./migrations/mm-config-cloud9.json
run migrations: ./node_modules/.bin/mm --config=./migrations/mm-config-cloud9.json migrate