import unreal
print("NOCTURNE_PYTHON_READY")
for key in ("Text3DActor", "Text3DComponent", "EditorActorSubsystem", "LevelEditorSubsystem", "MaterialEditingLibrary"):
    print(key, hasattr(unreal, key))
print("TEXT_METHODS", [x for x in dir(unreal.Text3DComponent) if "build" in x or "update" in x or "text" in x])
print("NOCTURNE_PROBE_DONE")
