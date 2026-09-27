"""Offscreen render experiment. Requires a working Metal RHI and compiled shaders."""
from pathlib import Path
import json
import unreal as ue

root = Path(__file__).resolve().parent
level = ue.get_editor_subsystem(ue.LevelEditorSubsystem)
if not globals().get("NOCTURNE_LEVEL_READY") and not level.load_level("/Game/Nocturne/CinematicIDE"):
    raise RuntimeError("Build the scene first with generate.command")
actors = ue.get_editor_subsystem(ue.EditorActorSubsystem)
world = ue.get_editor_subsystem(ue.UnrealEditorSubsystem).get_editor_world()
# get_statistics calls FinishCompilation in the installed UE source: avoid
# exporting a frame with the temporary checkerboard shader on new materials.
for path in ue.EditorAssetLibrary.list_assets("/Game/Nocturne/Materials", recursive=True, include_folder=False):
    material = ue.load_asset(path)
    if isinstance(material, ue.MaterialInterface):
        ue.MaterialEditingLibrary.get_statistics(material)
        print("NOCTURNE_MATERIAL_READY", path)
camera = next(a for a in actors.get_all_level_actors() if a.get_actor_label() == "NOCTURNE_Camera")
capture = actors.spawn_actor_from_class(ue.SceneCapture2D, camera.get_actor_location(), camera.get_actor_rotation())
capture.set_actor_label("NOCTURNE_OffscreenCapture")
component = capture.get_component_by_class(ue.SceneCaptureComponent2D)
target = ue.RenderingLibrary.create_render_target2d(world, 2560, 1600, ue.TextureRenderTargetFormat.RTF_RGBA8)
component.set_editor_property("texture_target", target)
component.set_editor_property("capture_source", ue.SceneCaptureSource.SCS_FINAL_COLOR_LDR)
component.set_editor_property("capture_every_frame", False)
component.set_editor_property("fov_angle", 48.4555)
settings = component.get_editor_property("post_process_settings")
settings.override_auto_exposure_method = True
settings.auto_exposure_method = ue.AutoExposureMethod.AEM_MANUAL
settings.override_auto_exposure_bias = True
settings.auto_exposure_bias = 0
component.set_editor_property("post_process_settings", settings)
component.capture_scene()
ue.RenderingLibrary.export_render_target(world, target, str(root), "nocturne-unreal.png")
output = root / "nocturne-unreal.png"
if not output.exists():
    raise RuntimeError("No exported image; render target was unavailable")
report = json.loads((root / "build-report.json").read_text())
report["rendered"] = False
report["render_status"] = "PNG exported; requires visual inspection before marking rendered:true. Previous commandlet capture was entirely black."
report["render_output"] = str(output.name)
(root / "build-report.json").write_text(json.dumps(report, indent=2))
print("NOCTURNE_RENDER_SAVED", output)
