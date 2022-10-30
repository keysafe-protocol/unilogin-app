drop table if exists user;
create table unilogin (
    uname varchar(80) not null,
    uaddr varchar(40) default '' not null,
    ukey varchar(300) default '' not null,
    PRIMARY KEY(uname)
);

