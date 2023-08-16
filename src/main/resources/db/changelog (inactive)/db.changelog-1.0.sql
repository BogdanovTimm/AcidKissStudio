create table customer
(
    id         bigint auto_increment
        primary key,
    address    varchar(255) null,
    created_at datetime(6)  null,
    email      varchar(255) null,
    image_url  varchar(255) null,
    name       varchar(255) null,
    phone      varchar(255) null,
    status     varchar(255) null,
    type       varchar(255) null
);
create table invoice
(
    id             bigint auto_increment
        primary key,
    date           datetime(6)  null,
    invoice_number varchar(255) null,
    services       varchar(255) null,
    status         varchar(255) null,
    total          double       not null,
    customer_id    bigint       not null,
    constraint FK5e32ukwo9uknwhylogvta4po6
        foreign key (customer_id) references customer (id)
);

create table users
(
    id         bigint unsigned auto_increment
        primary key,
    first_name varchar(50)                                                                  not null,
    last_name  varchar(50)                                                                  not null,
    email      varchar(100)                                                                 not null,
    password   varchar(255)                                                                 null,
    address    varchar(255)                                                                 null,
    phone      varchar(30)                                                                  null,
    title      varchar(50)                                                                  null,
    bio        varchar(255)                                                                 null,
    enabled    tinyint(1)   default 0                                                       null,
    non_locked tinyint(1)   default 1                                                       null,
    using_mfa  tinyint(1)   default 0                                                       null,
    created_at datetime     default CURRENT_TIMESTAMP                                       null,
    image_url  varchar(255) default 'https://cdn-icons-png.flaticon.com/512/149/149071.png' null,
    constraint UQ_Users_Email
        unique (email)
);

create table resetpasswordverifications
(
    id              bigint unsigned auto_increment
        primary key,
    user_id         bigint unsigned not null,
    url             varchar(255)    not null,
    expiration_date datetime        not null,
    constraint UQ_ResetPasswordVerifications_Url
        unique (url),
    constraint UQ_ResetPasswordVerifications_User_Id
        unique (user_id),
    constraint resetpasswordverifications_ibfk_1
        foreign key (user_id) references users (id)
            on update cascade on delete cascade
);

create table roles
(
    id         bigint unsigned auto_increment
        primary key,
    name       varchar(50)  not null,
    permission varchar(255) not null,
    constraint UQ_Roles_Name
        unique (name)
);

create table twofactorverifications
(
    id              bigint unsigned auto_increment
        primary key,
    user_id         bigint unsigned not null,
    code            varchar(10)     not null,
    expiration_date datetime        not null,
    constraint UQ_TwoFactorVerifications_Code
        unique (code),
    constraint UQ_TwoFactorVerifications_User_Id
        unique (user_id),
    constraint twofactorverifications_ibfk_1
        foreign key (user_id) references users (id)
            on update cascade on delete cascade
);



create table userroles
(
    id      bigint unsigned auto_increment
        primary key,
    user_id bigint unsigned not null,
    role_id bigint unsigned not null,
    constraint UQ_UserRoles_User_Id
        unique (user_id),
    constraint userroles_ibfk_1
        foreign key (user_id) references users (id)
            on update cascade on delete cascade,
    constraint userroles_ibfk_2
        foreign key (role_id) references roles (id)
            on update cascade
);

create table accountverifications
(
    id      bigint unsigned auto_increment
        primary key,
    user_id bigint unsigned not null,
    url     varchar(255)    not null,
    constraint UQ_AccountVerifications_Url
        unique (url),
    constraint UQ_AccountVerifications_User_Id
        unique (user_id),
    constraint accountverifications_ibfk_1
        foreign key (user_id) references users (id)
            on update cascade on delete cascade
);

create table events
(
    id          bigint unsigned auto_increment
        primary key,
    type        varchar(50)  not null,
    description varchar(255) not null,
    constraint UQ_Events_Type
        unique (type)
);

create table userevents
(
    id         bigint unsigned auto_increment
        primary key,
    user_id    bigint unsigned                    not null,
    event_id   bigint unsigned                    null,
    device     varchar(100)                       null,
    ip_address varchar(100)                       null,
    created_at datetime default CURRENT_TIMESTAMP null,
    constraint userevents_ibfk_1
        foreign key (user_id) references users (id)
            on update cascade on delete cascade,
    constraint userevents_ibfk_2
        foreign key (event_id) references events (id)
            on update cascade
);