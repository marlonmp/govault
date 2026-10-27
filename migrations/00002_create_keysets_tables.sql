-- +goose Up
create table keysets (
    keyset_id uuid primary key not null default gen_random_uuid(),
    user_id uuid unique not null,
    sequence_number smallint not null default 1 check (sequence_number >= 0),
    data jsonb not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

alter table keysets
    add constraint fk_user_keyset
    foreign key (user_id)
    references users (user_id)
    on delete restrict;

create index concurrently idx_keyset_sequence_number
    on keysets (sequence_number);

-- +goose Down
drop index concurrently if exists idx_keyset_sequence_number;

alter table keysets
    drop constraint if exists fk_user_keyset;

drop table if exists keysets;
