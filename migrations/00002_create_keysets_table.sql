-- +goose Up
create table keysets (
    keyset_id uuid primary key default gen_random_uuid(),
    user_id uuid unique not null,
    auth_salt varchar(64) not null,
    enc_salt varchar(64) not null,
    srp_verifier varchar(1024) not null,
    pub_key varchar(1024) not null,
    enc_priv_key varchar(1024) not null,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

alter table keysets
    add constraint fk_users_keysets
    foreign key (user_id)
    references users (user_id)
    on delete restrict;

-- +goose Down
alter table keysets
    drop constraint if exists fk_users_keysets;

drop table if exists keysets;

