"""Read the installed Xcode themes; retain original float RGBA values."""
import json, plistlib
from pathlib import Path
root=Path(__file__).resolve().parents[1]
base=Path('/Applications/Xcode.app/Contents/SharedFrameworks/DVTUserInterfaceKit.framework/Versions/A/Resources/FontAndColorThemes')
keys={'plain':'plain','keyword':'keyword','string':'string','number':'number','comment':'comment','preprocessor':'preprocessor','type':'identifier.type.system','function':'identifier.function','variable':'identifier.variable','systemFunction':'identifier.function.system','declaration':'declaration.other'}
def css_rgba(value):
    rgba=list(map(float,value.split()))
    return 'rgb('+ ' '.join(f'{v*100:.6f}%' for v in rgba[:3])+' / '+str(rgba[3])+')'

result={}
for kind in ['Dark','Light']:
    path=base/f'Default ({kind}).xccolortheme'
    data=plistlib.loads(path.read_bytes())
    raw=data['DVTSourceTextSyntaxColors']
    colors={}
    for name,key in keys.items():
        colors[name]=css_rgba(raw['xcode.syntax.'+key])
    selection_raw=data['DVTSourceTextSelectionColor']
    inactive_key=next((key for key in data if 'SourceText' in key and 'Selection' in key and ('Inactive' in key or 'Unfocused' in key)),None)
    inactive_raw=data[inactive_key] if inactive_key else ('0.24 0.25 0.28 1' if kind=='Dark' else '0.82 0.83 0.84 1')
    colors['selection']=css_rgba(selection_raw)
    colors['inactiveSelection']=css_rgba(inactive_raw)
    selection={'sourceKey':'DVTSourceTextSelectionColor','raw':selection_raw,'inactiveSourceKey':inactive_key,'inactiveRaw':inactive_raw,'inactiveNote':None if inactive_key else 'Neutral UI fallback: the installed Xcode default theme has no inactive selection field.'}
    result[kind.lower()]={'source':str(path),'raw':raw,'colors':colors,'selection':selection}
(root/'src/xcode-palette.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v['colors'] for k,v in result.items()},indent=2))
