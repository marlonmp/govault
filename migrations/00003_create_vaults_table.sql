-- +goose Up
create table vaults (
    vault_id uuid primary key default gen_random_uuid(),
    user_id uuid not null,
    title varchar(64) not null,
    enc_key text not null,
    content text not null,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

create table vaults_allowed_users (
    vault_id uuid not null,
    user_id uuid not null,
    can_sync boolean default false,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

alter table vaults
    add constraint fk_users_vaults
    foreign key (user_id)
    references users (user_id)
    on delete restrict;

alter table vaults_allowed_users
    add constraint fk_vaults_allowed_users
    foreign key (vault_id)
    references vaults (vault_id)
    on delete restrict;

alter table vaults_allowed_users
    add constraint fk_users_allowed_in_vault
    foreign key (user_id)
    references users (user_id)
    on delete restrict;

-- +goose Down
alter table vaults_allowed_users
    drop constraint if exists fk_users_allowed_in_vault;

alter table vaults_allowed_users
    drop constraint if exists fk_vaults_allowed_users;

alter table vaults
    drop constraint if exists fk_users_vaults;

drop table if exists vaults_allowed_users;

drop table if exists vaults;

