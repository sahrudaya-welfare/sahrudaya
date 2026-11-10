# SAHRUDAYA – Professional Community Organization Website

A modern, responsive community organization website built using Node.js, Express.js, and Neon (PostgreSQL) to showcase SAHRUDAYA's mission, leadership, services, and community initiatives.

---

## 🚀 Features

- Modern glass morphism UI with premium blue and purple theme
- Fully responsive design for desktop, tablet, and mobile
- Home, Who We Are, Services, Gallery, Executive Board, and Contact sections
- Contact form with arithmetic CAPTCHA verification
- Neon PostgreSQL database integration for storing contact messages securely
- Gallery with Previous/Next navigation
- Admin image upload and gallery management
- Sticky navigation with smooth scrolling
- Clean and scalable project structure

---

## 🛠️ Tech Stack

### Frontend
- HTML5
- CSS3
- JavaScript (Vanilla)

### Backend
- Node.js
- Express.js

### Database
- Neon PostgreSQL (pg)

---

## 📁 Project Structure

```
sahrudaya/
│── index.html          # Homepage
│── admin.html          # Admin Dashboard
│── server.js           # Express Server
│── styles.css          # Website Styling
│── package.json        # Project Dependencies
│── SWAN_LOGO.jpg       # Organization Logo
```

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/sahrudaya.git
cd sahrudaya
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment

Copy `.env.example` to `.env`, then replace the placeholder values with your Neon PostgreSQL connection string, a long random session secret, and a bcrypt hash for the admin password. `.env` is ignored by Git and must not be committed.

```bash
copy .env.example .env
```

Generate an admin password hash with:

```bash
node -e "require('bcrypt').hash('your-password', 12).then(console.log)"
```

SMTP settings are optional for local development. Without them, verification and password-reset links are printed in the server terminal; event notifications require SMTP.

### Admin login configuration

Set these values in `.env`. Use a long random value for `SESSION_SECRET`.

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=replace-with-a-bcrypt-hash
SESSION_SECRET=replace-with-a-long-random-secret
APP_BASE_URL=http://localhost:3000

# SMTP for registration, event, verification, and password reset emails
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-smtp-username
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=SAHRUDAYA <your-sender@example.com>
```

Put the generated hash in `ADMIN_PASSWORD_HASH`. Login attempts are limited to five failed attempts per IP address every 15 minutes.

### Member email setup

The server sends registration confirmations with verification links, password reset links, and new event announcements to verified members. For Gmail, set `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=465`, `SMTP_SECURE=true`, `SMTP_USER` to the Gmail address, and `SMTP_PASSWORD` to a Google App Password. The older `GMAIL_USER` and `GMAIL_APP_PASSWORD` variables remain supported as a Gmail-only fallback. Do not use a normal Gmail password or commit `.env`.

If SMTP variables are not configured, the server prints verification and reset links in the terminal for local development instead. Event notifications require SMTP to be configured.

Open `http://localhost:3000/admin` to sign in. The admin dashboard and the `GET /api/contacts` endpoint require an authenticated session.

### Gallery image uploads

After signing in, admins can upload JPEG, PNG, WebP, or GIF images up to 5 MB from the dashboard. Images are stored in the PostgreSQL `gallery_images` table and appear in the public gallery automatically.

### 4. Database Setup (Neon PostgreSQL)

Ensure your Neon database is active and set `DATABASE_URL` in `.env` to its connection string.

### 5. Run the application

```bash
npm start
```

Open your browser and visit:

```
http://localhost:3000
```

---

## 🔗 API Endpoints

| Method | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/contact` | Submit contact form with CAPTCHA verification |
| GET | `/api/contacts` | Retrieve all submitted contact messages |

---

## 📸 Gallery

The gallery is empty by default and supports Previous/Next navigation for uploaded images.

---

## 📞 Contact Form

The contact section includes:

- Name
- Email
- Subject
- Message
- Arithmetic CAPTCHA
- Neon PostgreSQL message storage

---

## 🎨 UI Features

- Glass Morphism Design
- Gradient Backgrounds
- Smooth Animations
- Responsive Layout
- Sticky Navigation
- Professional Color Palette

---

## 📈 Future Enhancements

- Admin Login
- Image Upload System
- Event Management
- Member Registration
- Newsletter Subscription
- Email Notifications
- Admin Dashboard Analytics

---

## 👨‍💻 Author

Developed by **R V S P C Murari**

---

## 📄 License

This project is licensed under the MIT License.
