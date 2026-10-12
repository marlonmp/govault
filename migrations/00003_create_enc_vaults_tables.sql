-- +goose Up
create table enc_vaults (
    enc_vault_id uuid primary key default gen_random_uuid(),
    created_by_id uuid not null,
    data jsonb not null,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

create table enc_vault_user (
    enc_vault_id uuid not null,
    user_id uuid not null,
    enc_sym_key jsonb not null,
    is_read_only boolean default false,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

alter table enc_vaults
    add constraint fk_created_by_enc_vault
    foreign key (created_by_id)
    references users (user_id)
    on delete restrict;

alter table enc_vault_user
    add constraint fk_enc_vault_user
    foreign key (enc_vault_id)
    references enc_vaults (enc_vault_id)
    on delete restrict;

alter table enc_vault_user
    add constraint fk_user_enc_vaults
    foreign key (user_id)
    references users (user_id)
    on delete restrict;

alter table enc_vault_user
    add constraint uq_user_enc_vault
    unique (user_id, vault_id);

-- +goose Down
alter table enc_vault_user
    drop constraint if exists uq_user_enc_vault;

alter table enc_vault_user
    drop constraint if exists fk_user_enc_vaults;

alter table enc_vault_user
    drop constraint if exists fk_enc_vault_user;

alter table enc_vaults
    drop constraint if exists fk_created_by_enc_vault;

drop table if exists enc_vault_user;

drop table if exists enc_vaults;
