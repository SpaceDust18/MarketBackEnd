import express from 'express';
import {
  createUser,
  getAllUsers,
  getUserById,
  updateUser,
  deleteUser
} from '../db/queries/users.js';
import { newUserCheck, verifyToken } from '../middleware.js';
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import db from '../db/client.js';

const router = express.Router();
const SECRET = process.env.JWT_SECRET || 'supersecretkey';

// POST /login - User login
router.post("/login", async (req, res, next) => {
  const { username, password } = req.body;

  try {
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required." });
    }

    const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (err) {
    next(err);
  }
});

// GET /users - Get all users (protected)
router.get('/', verifyToken, async (req, res, next) => {
  try {
    const users = await getAllUsers();
    res.json(users);
  } catch (error) {
    next(error);
  }
});

// POST /users - Create a new user
router.post('/', newUserCheck, async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await createUser(username, hashedPassword);

    const token = jwt.sign(
      { id: newUser.id, username: newUser.username },
      SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({
      token,
      user: {
        id: newUser.id,
        username: newUser.username
      }
    });
  } catch (error) {
    next(error);
  }
});

// PUT /users/:id - Update a user (protected)
router.put('/:id', verifyToken, async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const updatedUser = await updateUser(req.params.id, username, hashedPassword);

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(updatedUser);
  } catch (error) {
    next(error);
  }
});

// DELETE /users/:id - Delete a user by ID (protected)
router.delete('/:id', verifyToken, async (req, res, next) => {
  try {
    const deletedUser = await deleteUser(req.params.id);

    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    next(error);
  }
});

router.get('/reviews', verifyToken, async (req, res, next) => {
  const id = Number(req.user.id)
  try {
    const review = await db.query(`SELECT * FROM reviews WHERE user_id = $1;`, [id])
    res.status(201).json(review.rows)
  } catch (error) {

  }
});

router.post('/addtocart', verifyToken, async (req, res) => {
    const { productId } = req.body;
    const userId = req.user?.id;

    try {
        if (!productId || !userId) {
            return res.status(400).json({ error: "Missing productId or userId" });
        }

        // Insert into carts table
        await db.query(`
            INSERT INTO carts (user_id, product_id)
            VALUES ($1, $2)
        `, [userId, productId]);

        // Return full product info
        const result = await db.query(`
            SELECT p.*, 1 AS quantity
            FROM products p
            WHERE p.id = $1
        `, [productId]);

        const product = result.rows[0];
        product.price = parseFloat(product.price); // make sure price is a number

        res.status(201).json(product);
    } catch (err) {
        console.error("Error adding to cart:", err);
        res.status(500).json({ error: "Failed to add to cart" });
    }
});

// GET /users/:id - Get user by ID (protected)
router.get('/:id', verifyToken, async (req, res, next) => {
  try {
    const user = await getUserById(Number(req.params.id));
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    next(error);
  }
});


export default router;
