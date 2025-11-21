# ValidityVisionBNB

ValidityVisionBNB is a Flask-based smart expiry detection system that allows users to scan food product images, extract expiry dates using AI, store scan history, and receive notification alerts when expiry is near.

This project is created as part of our Innovation Challenge.

---

## 🚀 Features

### 🔐 User Authentication
- Register  
- Login  
- Logout  
- Welcome email sent only once on first registration

### 📊 User Dashboard
- Shows all scanned products
- Displays image, expiry date, and days left

### 📷 Product Scan
- Upload image
- AI extracts expiry date
- Saves record in firestore database

### 🔔 Email Notification
- Welcome email (first time only)
- Expiry alert email (if expiry < 5 days)

