-- User Sequence
CREATE SEQUENCE user_id_seq;

-- User table structure
CREATE TABLE users(
    id INTEGER DEFAULT nextval('user_id_seq') PRIMARY KEY,
    firstname TEXT NOT NULL,
    lastname TEXT NOT NULL,
    email TEXT CONSTRAINT customer_email_unique UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER',
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);


-- Token Sequence
CREATE sequence token_id_sequence;

-- Token table structure
CREATE TABLE if not exists token(
    id BIGINT DEFAULT nextval('token_id_sequence') PRIMARY KEY,
    user_id BIGINT NOT NULL,
    token varchar(500) CONSTRAINT token_token_unique UNIQUE NOT NULL,
    token_type varchar(10),
    expired boolean NOT NULL,
    revoked boolean NOT NULL,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
