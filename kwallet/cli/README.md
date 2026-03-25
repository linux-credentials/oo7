# kwallet-cli

Command-line tool for reading KWallet files.

## Usage

```bash
# Read wallet (prompts for password)
kwallet-cli ~/.local/share/kwalletd/kdewallet.kwl

# Provide password via argument
kwallet-cli wallet.kwl -p mypassword

# Export as JSON
kwallet-cli wallet.kwl --json

# Migrate to Secret Service
kwallet-cli wallet.kwl --migrate
```

## Output

Normal mode shows entries organized by folder:
```
📁 Passwords:
   🔑 mysite (password): secret123
   📋 github (map):
      username = user
      token = ghp_xxx
   📄 cert (stream): 2048 bytes
```

JSON mode outputs structured data:
```json
{
  "Passwords": {
    "mysite": {
      "type": "password",
      "value": "secret123"
    }
  }
}
```
