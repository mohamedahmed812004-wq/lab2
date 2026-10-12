# Lab 2: Login & To-Do Application

## 1. Team

| Name | ID | 
|------|----|
| Mohamed Ahmed Hussien|2204167 |


## 2. Technology

- **Back end:** Python 3 + Flask, PyMySQL (plain SQL, no ORM), bcrypt, python-dotenv
- **Front end:** Jinja templates, plain HTML/CSS (responsive, light and dark), vanilla JavaScript
- **Database:** MySQL 8, database `registration` (tables `users` and `todos`)

## 3. How to run it (from an empty machine, macOS)

1. Install Python 3.10+ and MySQL Server, and make sure MySQL is running.
2. Get the code and go into the folder:
   ```bash
   git clone <repo-url> && cd db-lab2-<names>
   ```
3. Install the dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
4. Build the database (this drops and recreates `registration`). Either run it from the terminal:
   ```bash
   mysql -u root -p < database/schema.sql
   ```
   or open `database/schema.sql` in SQLPro for MySQL and run the whole file.
5. Create your settings file and edit it (MySQL password and a long random `SECRET_KEY`):
   ```bash
   cp .env.example .env
   ```
6. Start the server:
   ```bash
   python app.py
   ```
7. Open <http://127.0.0.1:5000>.

## 4. Features

| # | Feature | Status |
|---|---------|--------|
| R1 | Register (name, e-mail, password, confirm). Duplicate e-mail shows `Email Already Exists`. User is logged in after registering | Done |
| R2 | Login with the same `Invalid email or password` message for a wrong e-mail or password; Logout ends the session | Done |
| R3 | Private list: not logged in means redirect to login; each user sees only their own to-dos, newest first | Done |
| R4-R7 | Add, edit title, mark done / not done, delete (with an "are you sure?" confirmation) | Done |
| R8 | Same checks in the browser (`static/app.js`) and on the server (`app.py`), with the exact messages; on a server error the page is shown again and the database is not touched | Done |
| R9 | bcrypt hashes, only the given queries, always with parameters, `user_id` always from the session | Done |
| R10 | Consistent responsive UI, error messages next to the fields, visible done state, empty state, name and Log out button, friendly error pages | Done |
| Bonus | Dark mode (follows the system setting), count of open / done to-dos | Done |

Extras: a CSRF token on every POST form, and a new session on every login.

## 5. Screenshots

`screenshots/` :

## 6. Answers

**(a) Why do `UPDATE` and `DELETE` contain `AND user_id = ?`, and what changes if you remove it?**
The `todo_id` comes from the browser, so anybody can send somebody else's number. `AND user_id = ?` uses the id of the logged-in user (from the session), so a to-do that is not yours matches zero rows and nothing changes. Without it, any logged-in user could edit or delete any other user's to-dos just by changing the number in the request.

**(b) What happens if you insert a to-do for a `user_id` that does not exist, and which constraint is that?**
MySQL refuses the insert with error 1452 (a foreign key constraint fails), because no row in `users` has that `user_id`. This is the **foreign key constraint**, which enforces **referential integrity**: a to-do can only point to a user that exists.

**(c) Why do you store a hash and not the password?**
If the database leaks, the attacker gets only hashes, not the passwords people use (often on other sites too). A bcrypt hash is one-way, salted (equal passwords give different hashes) and slow on purpose, which makes guessing expensive. To log in, the library compares the typed password with the stored hash; the real password is never stored.

**(d) The `name` column is `NOT NULL`: why do you still need your own check for an empty name?**
`NOT NULL` only forbids the value `NULL`. An empty text `''` is a value, so MySQL accepts it. Only our own checks (in the browser and again on the server) can refuse an empty name, and refuse a name made only of spaces.
