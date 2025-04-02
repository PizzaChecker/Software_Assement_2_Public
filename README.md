### Environment Setup

1. **Create a virtual environment**:
   ```bash
   python3 -m venv env
   ```

2. **Set execution policy (Windows only)**:
   Temporarily allow script execution for the current terminal session:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

3. **Activate the virtual environment**:
   ```bash
   env\Scripts\Activate  # Windows
   source env/bin/activate  # macOS/Linux
   ```

4. **Create a `.gitignore` file**:
   Use the following command to create a `.gitignore` file:
   ```bash
   touch .gitignore
   ```
   Add the following lines to the `.gitignore` file to prevent uploading sensitive files:
   ```
   env/
   .env
   ```

5. **Set environment variables**:
   Add the following environment variables (replace `put_secret_key_here` with your actual secret keys):
   ```powershell
   $env:VSCODE_DOM="put_secret_key_here"
   $env:VSCODE_SK_="put_secret_key_here"
   ```
   Example values:
   ```
   CajnoXYH-sBaXYYlgznRUfGolxVklLR-GpebSEUSnkg=
   _5#y2L"F4Q8z\n\xec]/
   ```

6. **View all environment variables** (optional):
   ```powershell
   Get-ChildItem Env:
   ```

7. **Install required Python packages**:
   Run the following commands to install all necessary dependencies:
   ```bash
   pip install flask
   pip install flask-csp
   pip install pillow
   pip install bcrypt
   pip install cryptography
   pip install Flask-WTF
   pip install requests
   pip install pytest
   ```

8. **Verify installation**:
   Ensure all packages are installed correctly by running:
   ```bash
   pip list
   ```

### Notes
- Ensure Python 3 is installed on your system.
- Use a secure method to store and manage secret keys (e.g., `.env` file or environment variables).
