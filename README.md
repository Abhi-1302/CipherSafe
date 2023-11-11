# CipherSafe
CipherSafe is a secure password manager application built using Python's Tkinter GUI and SQLite for database management. It provides a safe vault to store website credentials securely encrypted.

## Features

- **Encryption:** Utilizes Fernet encryption for securing sensitive data.
- **Master Password:** Set up a master password to access the vault.
- **Recovery Key:** Option to save a recovery key for account retrieval.
- **Vault Management:** Add, view, and remove stored website credentials.
  

## Usage

1. **Setting Up:**
    - Launch the application (`CipherSafe.py`).
    - If it's your first time, you'll be prompted to set a master password.
    - Save the recovery key generated for account restoration.

2. **Logging In:**
    - Use the set master password to access the vault.
    - Reset the master password using the recovery key if forgotten.

3. **Managing Credentials:**
    - Add new entries with website, username, and password details.
    - Remove stored credentials as needed.

## Contributing

Contributions are welcome! If you'd like to contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your_feature`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature/your_feature`).
5. Create a new Pull Request.
