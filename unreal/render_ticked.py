"""Try capture after real editor ticks; RenderOffScreen suppresses the main window."""
from pathlib import Path
import traceback
import unreal as ue

ROOT = Path(__file__).resolve().parent
ue.get_editor_subsystem(ue.LevelEditorSubsystem).load_level("/Game/Nocturne/CinematicIDE")
_ticks = 0
_handle = None

def on_tick(delta):
    global _ticks
    _ticks += 1
    if _ticks < 90:
        return
    ue.unregister_slate_post_tick_callback(_handle)
    try:
        path = ROOT / "render_scene.py"
        exec(compile(path.read_text(), str(path), "exec"), {"__file__": str(path), "NOCTURNE_LEVEL_READY": True})
    except Exception:
        ue.log_error(traceback.format_exc())
    finally:
        ue.SystemLibrary.quit_editor()

_handle = ue.register_slate_post_tick_callback(on_tick)
