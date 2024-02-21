from setuptools import setup

setup(
    name            = 'async-bithumb',
    version         = '1.0.0',
    description     = 'Asynchronus pybithumb library. Based on pybithumb library: https://github.com/sharebook-kr/pybithumb',
    url             = 'https://github.com/sharebook-kr/pybithumb',
    author          = 'Lukas Yoo, Brayden Jo, pakchu',
    author_email    = 'jonghun.yoo@outlook.com, pystock@outlook.com, gus4734@gmail.com',
    install_requires= ['pandas', 'aiohttp'],
    license         = 'MIT',
    packages        = ['async_bithumb'],
    zip_safe        = False
)
