import base64, urllib, hashlib, hmac, time
import aiohttp


class PublicApi:
    @staticmethod
    async def ticker(order_currency, payment_currency="KRW"):
        uri = "/public/ticker/{}_{}".format(order_currency, payment_currency)
        return await BithumbHttp().get(uri)

    @staticmethod
    async def transaction_history(order_currency, payment_currency="KRW", limit=20):
        uri = "/public/transaction_history/{}_{}?count={}".format(order_currency,
                                                    payment_currency,
                                                    limit)
        return await BithumbHttp().get(uri)

    @staticmethod
    async def orderbook(order_currency, payment_currency="KRW", limit=5):
        uri = "/public/orderbook/{}_{}?count={}".format(order_currency,
                                                     payment_currency, limit)
        return await BithumbHttp().get(uri)

    @staticmethod
    async def btci():
        uri = "/public/btci"
        return await BithumbHttp().get(uri)

    @staticmethod
    async def candlestick(order_currency, payment_currency="KRW", chart_intervals="24h"):
        uri = "/public/candlestick/{}_{}/{}".format(order_currency, payment_currency,
                                                chart_intervals)
        return await BithumbHttp().get(uri)


class PrivateApi:
    def __init__(self, conkey, seckey):
        self.http = BithumbHttp(conkey, seckey)

    async def account(self, **kwargs):
        return await self.http.post('/info/account', **kwargs)

    async def balance(self, **kwargs):
        return await self.http.post('/info/balance', **kwargs)

    async def place(self, **kwargs):
        return await self.http.post('/trade/place', **kwargs)

    async def orders(self, **kwargs):
        return await self.http.post('/info/orders', **kwargs)

    async def order_detail(self, **kwargs):
        return await self.http.post('/info/order_detail', **kwargs)

    async def cancel(self, **kwargs):
        return await self.http.post('/trade/cancel', **kwargs)

    async def market_buy(self, **kwargs):
        return await self.http.post('/trade/market_buy', **kwargs)

    async def market_sell(self, **kwargs):
        return await self.http.post('/trade/market_sell', **kwargs)

    async def withdraw_coin(self, **kwargs):
        return await self.http.post('/trade/btc_withdrawal', **kwargs)

    async def withdraw_cash(self, **kwargs):
        return await self.http.post('/trade/krw_withdrawal', **kwargs)

class HttpMethod:
    def __init__(self):
        self.session = aiohttp.ClientSession()

    @property
    def base_url(self):
        return ""

    async def update_headers(self, headers):
        self.session.headers.update(headers)

    async def post(self, path, timeout=3, **kwargs):
        try:
            uri = self.base_url + path
            async with self.session.post(url=uri, data=kwargs, timeout=timeout) as response:
                return await response.json()
        except Exception as x:
            print("It failed", x.__class__.__name__)
            return None

    async def get(self, path, timeout=3, **kwargs):
        try:
            uri = self.base_url + path
            async with self.session.get(url=uri, params=kwargs, timeout=timeout) as response:
                return await response.json()
        except Exception as x:
            print("It failed", x.__class__.__name__)
            return None

class BithumbHttp(HttpMethod):
    def __init__(self, conkey="", seckey=""):
        self.API_CONKEY = conkey.encode('utf-8')
        self.API_SECRET = seckey.encode('utf-8')
        super(BithumbHttp, self).__init__()

    @property
    def base_url(self):
        return "https://api.bithumb.com"

    def _signature(self, path, nonce, **kwargs):
        query_string = path + chr(0) + urllib.parse.urlencode(kwargs) + \
                       chr(0) + nonce
        h = hmac.new(self.API_SECRET, query_string.encode('utf-8'),
                     hashlib.sha512)
        return base64.b64encode(h.hexdigest().encode('utf-8'))

    async def post(self, path, **kwargs):
        kwargs['endpoint'] = path
        nonce = str(int(time.time() * 1000))

        await self.update_headers({
            'Api-Key': self.API_CONKEY,
            'Api-Sign': self._signature(path, nonce, **kwargs),
            'Api-Nonce': nonce
        })
        return await super().post(path, **kwargs)

if __name__ == "__main__":
    print(PublicApi.ticker("BTC"))