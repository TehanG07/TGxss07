
# Run the Tool

cd TGxss07
chmod +x tgxss07.py

# More information 

# TGxss07

**TGxss07** is a tool for finding XSS vulnerabilities in web applications.

# setup.py

pip install .

## Usage

# Note:- if first command not run than try secound command.

cd TGxss07

# single url

python tgxss07.py -u http://example.com -p payload.json payload.txt -r ./results

./python tgxss07.py -u http://example.com -p payload.json payload.txt  -r ./result

# multiple url

python tgxss07.py -l urls.txt -p payload.json payload.txt -r result

./python tgxss07.py -l urls.txt -p payload.json payload.txt  -r ./result

# multiple domains/sub-domains 

python tgxss07.py -dL domains.txt -p payload.json payload.txt -r result

./python tgxss07.py -dL domains.txt -p payload.json payload.txt -r ./result


