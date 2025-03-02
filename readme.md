# MyInfo Integration with Django REST Framework

## Installation

### Using `uv`
```sh
uv sync
```

### Using `pip` manually
```sh
python -m venv env
source env/bin/activate  # Linux/macOS
env\Scripts\activate    # Windows
pip install -r requirements.txt
```

## 🚀 Running the Server
```sh
python manage.py runserver localhost:3001
```

The server will run at **http://localhost:3001**.

## Manual Testing

1. Open up the browser and navigate to **http://localhost:3001/auth**.
2. it will give response like this
```json
"https://test.api.myinfo.gov.sg/com/v4/authorize?client_id=STG-202327956K-ABNK-BNPLAPPLN&scope=uinfin%20name%20sex%20race%20dob%20residentialstatus%20nationality%20birthcountry%20passtype%20passstatus%20passexpirydate%20employmentsector%20mobileno%20email%20regadd%20housingtype%20hdbtype%20cpfcontributions%20noahistory%20ownerprivate%20employment%20occupation%20cpfemployers%20marital&purpose_id=7ed6f2ce&response_type=code&code_challenge=rEcY1rQkVVhekmVV5jd96GpSNQBT2AodREYpQZunlrs&code_challenge_method=S256&redirect_uri=http://localhost:3001/callback"
```
3. Open up this SingPass Authorise URL and follow instructions
4. After clicking on the "Login" button, you'll be redirected back to a callback URL like this
```sh
https://test.api.myinfo.gov.sg/serviceauth/myinfo-com/v2/authorize?aud=https%3A%2F%2Ftest.api.myinfo.gov.sg%2Fcom%2Fv4%2Fperson&client_id=STG-202327956K-ABNK-BNPLAPPLN&code_challenge=HjTq5Qiozdvnk0vc4XI8K1WQTwKbkTJoL3CL8BV1ZaA&code_challenge_method=S256&purpose_id=7ed6f2ce&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&response_type=code&scope=uinfin%2Bname%2Bsex%2Brace%2Bdob%2Bresidentialstatus%2Bnationality%2Bbirthcountry%2Bpasstype%2Bpassstatus%2Bpassexpirydate%2Bemploymentsector%2Bmobileno%2Bemail%2Bregadd%2Bhousingtype%2Bhdbtype%2Bcpfcontributions%2Bnoahistory%2Bownerprivate%2Bemployment%2Boccupation%2Bcpfemployers%2Bmarital
```
4. after you push button "I Agree" you will be redirected to the callback URL like this
```sh
http://localhost:3001/callback?code=myinfo-com-DzZq8JgRVVsxkzOn4yMvaf4SQi6UmDEmRyUty2SO
```
and will give response like this
```json
{
  "employmentsector": {
    "lastupdated": "2024-01-26",
    "source": "3",
    "classification": "C",
    "value": ""
  },
  "uinfin": {
    "lastupdated": "2024-01-26",
    "source": "1",
    "classification": "C",
    "value": "S0290695C"
  },
  "name": {
    "lastupdated": "2024-01-26",
    "source": "1",
    "classification": "C",
    "value": "BERNARD LI GUO HAO"
  },
  "sex": {
    "lastupdated": "2024-01-26",
    "code": "F",
    "source": "1",
    "classification": "C",
    "desc": "FEMALE"
  },
  "occupation": {
    "lastupdated": "2024-01-26",
    "source": "2",
    "classification": "C",
    "value": ""
  },
  "cpfemployers": {
    "lastupdated": "2024-01-26",
    "source": "1",
    "history": [
      {
        "month": {
          "value": "2022-10"
        },
        "employer": {
          "value": "DBS BANK LTD"
        }
      }
    ]
  },
  "marital": {
    "lastupdated": "2024-01-26",
    "code": "1",
    "source": "1",
    "classification": "C",
    "desc": "SINGLE"
  }
  // and more
}
```