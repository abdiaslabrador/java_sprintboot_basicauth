-- Insert data
INSERT INTO roles (id_role, name) VALUES (DEFAULT, 'ROLE_USER');
INSERT INTO roles (id_role, name) VALUES (DEFAULT, 'ROLE_ADMIN');

INSERT INTO users (id_user, username, password) VALUES (default, 'pepe', '$2a$12$8LegtLQWe717tIPvZeivjuqKnaAs5.bm0Q05.5GrAmcKzXw2NjoUO');
INSERT INTO users (id_user, username, password) VALUES (default, 'pepa', '$2a$12$8LegtLQWe717tIPvZeivjuqKnaAs5.bm0Q05.5GrAmcKzXw2NjoUO');


INSERT INTO profiles (id_profile, email, address, user_id) VALUES (DEFAULT, 'pepe@mail.com', 'portal 1', 1);
INSERT INTO profiles (id_profile, email, address, user_id) VALUES (DEFAULT, 'pepa@mail.com', 'portal 1', 2);

INSERT INTO roles_users (role_id, user_id) VALUES (1, 1);
INSERT INTO roles_users (role_id, user_id) VALUES (2, 2);