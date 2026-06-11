import zipfile
from xml.etree import ElementTree as ET
fn = "Conception du Système d'authentification.docx"
with zipfile.ZipFile(fn, 'r') as z:
    data = z.read('word/document.xml')
root = ET.fromstring(data)
ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
for i, p in enumerate(root.findall('.//w:p', ns)):
    texts = [t.text for t in p.findall('.//w:t', ns) if t.text]
    if texts:
        print(f'{i:03}: {"".join(texts)}')
