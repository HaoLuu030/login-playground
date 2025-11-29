import express from "express";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";


const _filename = fileURLToPath(import.meta.url);
const _dirname = path.dirname(_filename);


const app = express();


app.use(express.json());
app.use(cors());
app.use(express.static(path.join(_dirname, "public")));


const db = new sqlite3.Database("./database.db");

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
    )`);


app.post("/register", async(req, res) => {
    const {username, password} = req.body;

    const hashed = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users(username, password) VALUES (?, ?)",
        [username, hashed],
        (err) => {
            if (err) {
                if(err.code === "SQLITE_CONSTRAINT") {
                    return res.json({
                        succes: false,
                        message: "Username already exists"
                    });
                }


                return res.json({
                    success: false,
                    message: "Database error",
                    detail: err.message
                })
            }
            res.json({success: true});
        }
    )
})




app.post("/login", (req, res) => {
    console.log(req.body);
    const {username, password} = req.body;

    db.get(
        "SELECT * FROM users WHERE username =?",
        [username],
        async(err, user) => {
            if (!user) {
                return res.json({success: false, message: "User not found"});
            }

            const ok = await bcrypt.compare(password, user.password);
            if (!ok) {
                return res.json({success: false, message: "wrong password"});
            }

            res.json({success: true});
        }
    );
})


app.get("/admin/users", (req, res) => {
    db.all("SELECT id, username FROM users", [], (err, rows) => {
        if (err) {
            return res.json({ success: false, error: err.message });
        }
        res.json(rows); // send all users as JSON
    });
});

app.listen(3000, () => console.log("server running at http://localhost:3000"));