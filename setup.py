import setuptools

setuptools.setup(
    name="BTG",
    packages=["BTG"],
    version="2.0",
    author="Conix Security",
    author_email="robin.marsollier@conix.fr",
    description="This tool allows you to qualify one or more potential malicious observables of various type (URL, MD5, SHA1, SHA256, SHA512, IPv4, IPv6, domain etc..)",
    url="https://github.com/conix-security/BTG",
    keywords = ['ioc'],
    classifiers=(
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
	'Topic :: Internet',
    ),
)
