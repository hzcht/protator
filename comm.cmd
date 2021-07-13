git config --global user.name "Pochtar"
git config --global user.email "i@vasilenko.me"

go fmt .
git config core.autocrlf true
git remote add master git clone https://pochtar@bitbucket.org/pochtar/protator.git
git add -A
git add -A *
curl -s http://whatthecommit.com/index.txt >comm.txt

git commit -a -F comm.txt
del comm.txt
git  push