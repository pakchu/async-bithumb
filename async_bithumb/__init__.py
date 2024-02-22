from .client import Bithumb
from .websocket import WebSocketManager

__version__ = "1.0.3"

async def get_ohlc(order_currency, payment_currency="KRW"):
    return await Bithumb.get_ohlc(order_currency, payment_currency)

async def get_tickers(payment_currency="KRW"):
    return await Bithumb.get_tickers(payment_currency)

async def get_market_detail(order_currency, payment_currency="KRW"):
    return await Bithumb.get_market_detail(order_currency, payment_currency)

async def get_current_price(order_currency, payment_currency="KRW"):
    return await Bithumb.get_current_price(order_currency, payment_currency)

async def get_orderbook(order_currency, payment_currency="KRW", limit=5):
    return await Bithumb.get_orderbook(order_currency, payment_currency, limit)

async def get_transaction_history(order_currency, payment_currency="KRW", limit=20):
    return await Bithumb.get_transaction_history(order_currency, payment_currency, limit)

async def get_candlestick(order_currency, payment_currency="KRW", chart_intervals="24h"):
    return await Bithumb.get_candlestick(order_currency, payment_currency, chart_intervals)

# @util.deprecated('Please use get_candlestick() function instead of get_ohlcv().')
async def get_ohlcv(order_currency="BTC", payment_currency="KRW", interval="day"):
    # for backward compatibility
    chart_instervals = {
        "day": "24h",
        "hour12": "12h",
        "hour6": "6h",
        "hour": "1h",
        "minute30": "30m",
        "minute10": "10m",
        "minute5": "5m",
        "minute3": "3m",
        "minute1": "1m",
    }[interval]

    return await Bithumb.get_candlestick(order_currency, payment_currency, chart_instervals)