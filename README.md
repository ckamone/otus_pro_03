# app info
scoring app

## venv
cd /home/user/otus/
. venv/bin/activate

## run redis in docker 
docker run -p 6379:6379 --rm --name test-redis redis:6.2-alpine redis-server

## how to test via unittest
cd /home/user/otus/project/
python3 -m unittest discover -s tests/unit
python3 -m unittest discover -s tests/functional
python3 -m unittest discover -s tests/integration (works only with redis)

## test api
python3 api.py
curl -X POST  -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af34e14e1d5bcd5a08f21fc95", "arguments": {"phone": "79175002040", "email": "random@otus.ru", "first_name": "Name", "last_name": "Surname", "birthday": "01.01.1990", "gender": 1}}' http://127.0.0.1:8080/method/
