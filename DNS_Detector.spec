# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['DNS_Detector.py'],
    pathex=[],
    binaries=[],
    datas=[('icon.ico', '.')],
    hiddenimports=['sklearn.utils._weight_vector', 'sklearn.neighbors._quad_tree', 'sklearn.tree._utils', 'torch', 'torchvision'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['torch.testing', 'torch.distributed'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='DNS_Detector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['icon.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='DNS_Detector',
)
