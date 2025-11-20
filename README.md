# Image-Based Password Security Generator
------------------------------------------
A simple, transparent, and secure password manager that generates unique password prefixes based on your personal images. Built with Python for complete code transparency and user trust.

Created by YazTeKs https://yazteks.com/

Security Features
------------------

- Image-Based Security: Uses perceptual hashing of your personal images combined with user credentials
- Strong Encryption: PBKDF2-HMAC-SHA256 with 100,000 iterations
- Unique Salts: Each entry gets its own random 32-byte salt
- Local Storage: All data stored locally in SQLite - no cloud, no network calls
- Open Source: Single Python file you can read and audit yourself

Requirements
-------------
- Python 3.7 or higher
- Two dependencies:
  ```bash
  pip install Pillow imagehash
  ```

How It Works
-------------
1. Image Selection: Choose any personal image (photo, artwork, etc.)
2. Perceptual Hashing: The app creates a hash of the image's visual content
3. Data Combination: Combines username + service + image hash + first 1KB of file
4. Key Derivation: Uses PBKDF2 with 100,000 iterations and unique salt
5. Prefix Generation: Generates a URL-safe base64 string of your chosen length

Why This Is Secure
------------------
- Multiple Factor: Requires something you know (username/service) + something you have (image)
- No Password Storage: Only stores salts and metadata, not the actual passwords
- Deterministic: Same inputs always produce the same output
- Collision Resistant: Cryptographic hashing makes it virtually impossible to reverse

Data Storage
------------------
The application stores:
- Username and service name
- Image perceptual hash (not the image itself)
- Random salt for key derivation
- Generated password prefix
- Creation and last-used timestamps

Database location: `password_manager.db` in the same directory as the script


Features
---------
- Generate unique password prefixes from images
- Save entries for easy regeneration
- Configurable prefix length (8-24 characters)
- Copy to clipboard functionality
- View and manage saved entries
- Regenerate passwords from saved entries
- Delete old entries
- Clean, modern GUI

Desktop GUI Application
------------------------
To obtain a standalone executable, please contact YazTeKs at https://yazteks.com/.


Contributing
--------------
This is open source software - contributions are welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests
- Audit the security

Disclaimer
-----------
While this application uses standard cryptographic methods, no password manager is 100% secure. Use at your own risk. Always:
- Keep backups of your images and database
- Use additional security measures (2FA, password managers)
- Don't rely on this as your only security method

License
--------
MIT License - Free to use, modify, and distribute

Copyright (c) 2025 YazTeKs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to use, copy, modify, merge, publish and/or distribute the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

-------------------------------------------------------------------------------------------
** Made by YazTeKs for security-conscious users who believe in open source transparency **
-------------------------------------------------------------------------------------------

