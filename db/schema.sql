DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products CASCADE;
DROP TABLE IF EXISTS reviews;

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE orders (
 id SERIAL PRIMARY KEY,
 date DATE NOT NULL,
 note TEXT,
 user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE products(
    id SERIAL PRIMARY KEY,
    title TEXT UNIQUE NOT NULL,
    image_url TEXT NOT NULL,
    flavor TEXT NOT NULL,
    price DECIMAL NOT NULL,
    dose TEXT NOT NULL,
    total TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    strain TEXT NOT NULL,
    potency TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE reviews(
    id SERIAL PRIMARY KEY,
    rating INTEGER NOT NULL,
    comment TEXT,
    product_id INTEGER NOT NULL,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);