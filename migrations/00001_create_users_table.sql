-- +goose Up
create table users (
    user_id uuid primary key default gen_random_uuid(),
    nickname varchar(32) not null,
    email varchar(128) unique not null,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

-- +goose Down
drop table if exists users;

