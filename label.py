import pickle, json
pkl = r'c:\Users\Matt.Palmer\Documents\GitHub\BlueTeam\AI\label_encoder.pkl'
out = r'c:\Users\Matt.Palmer\Documents\GitHub\BlueTeam\AI\label_map.json'
with open(pkl,'rb') as f:
    obj = pickle.load(f)
mapping = {}
# sklearn LabelEncoder
classes = getattr(obj, 'classes_', None)
if classes is not None:
    mapping = {i: str(c) for i,c in enumerate(classes)}
elif isinstance(obj, dict):
    mapping = {int(k):v for k,v in obj.items()}
else:
    raise SystemExit("Unsupported pickle type; convert to dict or LabelEncoder")
with open(out,'w',encoding='utf-8') as fh:
    json.dump(mapping, fh, indent=2)
print('Wrote', out)