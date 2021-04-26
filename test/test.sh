cd ..
python3 setup.py build --force
sudo python3 setup.py install
python3 -m pytest
