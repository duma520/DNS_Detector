cls
rmdir /s /q build
rmdir /s /q dist
pyinstaller --noconfirm --windowed --icon=icon.ico --add-data "icon.ico;." --hidden-import sklearn.utils._weight_vector --hidden-import sklearn.neighbors._quad_tree --hidden-import sklearn.tree._utils --hidden-import torch --hidden-import torchvision --exclude-module torch.testing --exclude-module torch.distributed DNS_Detector.py