create table if not exists connections (
                                           src_ip text not null,
                                           dst_ip text not null,
                                           dst_dns text not null default '',
                                           host_name text not null default '',
                                           created_at text not null
);

create index if not exists idx_connections_dst_ip_created_at
    on connections (dst_ip, created_at);

create index if not exists idx_connections_dst_dns
    on connections (dst_dns);


create table if not exists domain_conn_counts (
                                                  dst_dns text primary key,
                                                  active_connections integer not null,
                                                  updated_at text not null
);

create index if not exists idx_domain_conn_counts_active
    on domain_conn_counts (active_connections);

create index if not exists idx_domain_conn_counts_updated
    on domain_conn_counts (updated_at);


create table if not exists dst_conn_counts (
                                               dst_ip text not null,
                                               dst_dns text not null default '',
                                               active_connections integer not null,
                                               updated_at text not null,
                                               primary key (dst_ip, dst_dns)
    );

create index if not exists idx_dst_conn_counts_dns
    on dst_conn_counts (dst_dns);

create index if not exists idx_dst_conn_counts_active
    on dst_conn_counts (active_connections);

create index if not exists idx_dst_conn_counts_updated
    on dst_conn_counts (updated_at);
