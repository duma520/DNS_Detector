cls
rmdir /s /q build
rmdir /s /q dist
python -m nuitka --standalone --windows-disable-console --plugin-enable=pyqt6 --output-dir=dist DNS_Detector.py