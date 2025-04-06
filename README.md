# Cryptogoblin
This is a python module I am writing as I work through the [cryptopals challenges](https://cryptopals.com/).

It is written so that the module can be built and then the challenges' solutions tested as a `testpy` routine.

The module can be installed with the following commands:

```console
git clone https://github.com/Gabriele-Ricciardi/cryptogoblin.git
cd cryptogoblin
python -m venv venv
source venv/bin/activate
pip install build pytest
python -m build
pip install dist/*.whl
deactivate && source venv/bin/activate
```
and the tests run with:
```console
pytest
```

The algorithms implemented in this module have been written as a study exercise, adherent to the various RFC/FIPS documents,
and are not implemented with extreme efficiency in mind (e.g. actual matrix multiplications vs lookup tables). 
In any case, this module should not be used for anything except cryptography studies, and any use in production
environments is heavily discouraged.
