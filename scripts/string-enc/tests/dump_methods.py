import sys
sys.path.insert(0, '.')
from androguard.core.bytecodes import apk as apkmod, dvm

path = sys.argv[1]
raw = open(path, 'rb').read()
if raw[:4] == b'PK\x03\x04':
    import io
    a = apkmod.APK(raw, raw=True)
    for dex in a.get_all_dex():
        d = dvm.DalvikVMFormat(dex)
        for m in d.get_methods():
            print(''.join((m.get_class_name(), m.get_name(), m.get_descriptor())))
else:
    d = dvm.DalvikVMFormat(raw)
    for m in d.get_methods():
        print(''.join((m.get_class_name(), m.get_name(), m.get_descriptor())))
