-- +goose Up
create table users (
    user_id uuid primary key default gen_random_uuid(),
    nickname varchar(32) not null,
    email varchar(128) unique not null,
    secret_key jsonb,
    auth jsonb,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

create table email_verification (
    verification_id uuid primary key default get_random_uuid()
    user_id uuid not null,
    otp varchar(6) not null,
    created_at timestamptz default now(),
    expires_at timestamptz not null,
    applied_at timestamptz,
);

create table devices (
    device_id uuid primary key default get_random_uuid()
    user_id uuid not null,
    data jsonb not null,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

alter table email_verification
    add constraint fk_user_email_verification
    foreign key (user_id)
    references users (user_id)
    on delete restrict;

alter table devices
    add constraint fk_user_device
    foreign key (user_id)
    references users (user_id)
    on delete restrict;

-- +goose Down
alter table devices
    drop constraint if exists fk_user_device;

alter table email_verification
    drop constraint if exists fk_user_email_verification;

drop table if exists devices;

drop table if exists email_verification;

drop table if exists users;
