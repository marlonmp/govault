# Manage migrations

For this project we will use [Goose](https://pressly.github.io/goose/) a simple and esay to use database migration tool.

## Goose instalation

For the goose installation I strongly recommend to follow [the official goose install guide](https://pressly.github.io/goose/installation/) to install goose on your device.

After install make sure goose was installed properly by running the next command:

```bash
goose --version
```

## Goose set up

Goose offers many ways to configure the database connection, but for this project we will use a `.env` config. Make sure to have the `.env` file in the root of your project and configure the next variables:

```bash
GOOSE_MIGRATION_DIR=./migrations
GOOSE_DRIVER=<driver-name>
GOOSE_DBSTRING=<driver-uri>
```
> NOTE: in the .env.example you have all the variables default config

Make sure the connection with the database is successful with the next command:

```bash
goose status
```

### Create migrations

To create a secuential migration we will run this command:

```bash
goose create -s <migration-name> sql
```

### Applying migrations

To apply all the unapplied migrations in the database run the next command:

```bash
goose up
```

### Reverse a migrations

To reverse one migration in the database run the next command:

```bash
goose down
```

