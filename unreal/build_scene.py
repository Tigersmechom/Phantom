"""Generate actual beveled Text3D meshes; run with UE's Python commandlet."""
from pathlib import Path
import json
import unreal as ue

ROOT = Path(__file__).resolve().parent
ASSETS = "/Game/Nocturne"
MAP = ASSETS + "/CinematicIDE"
actors = ue.get_editor_subsystem(ue.EditorActorSubsystem)
levels = ue.get_editor_subsystem(ue.LevelEditorSubsystem)
assets = ue.AssetToolsHelpers.get_asset_tools()
palette = json.loads((ROOT.parent / "src/xcode-palette.json").read_text())["dark"]["raw"]

def linear(value):
    return value / 12.92 if value <= 0.04045 else ((value + .055) / 1.055) ** 2.4

def color(category):
    rgb = [float(v) for v in palette["xcode.syntax." + category].split()]
    return ue.LinearColor(*[linear(v) for v in rgb[:3]], rgb[3])

def material(name, rgb, metallic=0.0, roughness=.35, emissive=False):
    path = ASSETS + "/Materials/" + name
    existing = ue.load_asset(path) if ue.EditorAssetLibrary.does_asset_exist(path) else None
    if existing:
        return existing
    result = assets.create_asset(name, ASSETS + "/Materials", ue.Material, ue.MaterialFactoryNew())
    constant = ue.MaterialEditingLibrary.create_material_expression(result, ue.MaterialExpressionConstant3Vector)
    constant.set_editor_property("constant", rgb)
    if emissive:
        result.set_editor_property("shading_model", ue.MaterialShadingModel.MSM_UNLIT)
        ue.MaterialEditingLibrary.connect_material_property(constant, "", ue.MaterialProperty.MP_EMISSIVE_COLOR)
    else:
        ue.MaterialEditingLibrary.connect_material_property(constant, "", ue.MaterialProperty.MP_BASE_COLOR)
        for value, prop in [(metallic, ue.MaterialProperty.MP_METALLIC), (roughness, ue.MaterialProperty.MP_ROUGHNESS)]:
            scalar = ue.MaterialEditingLibrary.create_material_expression(result, ue.MaterialExpressionConstant)
            scalar.set_editor_property("r", value)
            ue.MaterialEditingLibrary.connect_material_property(scalar, "", prop)
    ue.MaterialEditingLibrary.recompile_material(result)
    ue.EditorAssetLibrary.save_loaded_asset(result)
    return result

if ue.EditorAssetLibrary.does_asset_exist(MAP):
    # A repeat run replaces actors only in this generated experiment map.
    if not levels.load_level(MAP):
        raise RuntimeError("Could not create/load " + MAP)
    for actor in actors.get_all_level_actors():
        if actor.get_actor_label().startswith("NOCTURNE_"):
            actors.destroy_actor(actor)
elif not levels.new_level(MAP):
    raise RuntimeError("Could not create " + MAP)

categories = {
    "plain": "plain", "keyword": "keyword", "comment": "comment",
    "number": "number", "string": "string", "type": "identifier.type.system",
    "variable": "identifier.variable", "function": "identifier.function",
    "preprocessor": "preprocessor", "declaration": "declaration.other",
}
front = {key: material("Xcode_" + key, color(category), emissive=True) for key, category in categories.items()}
side = material("ObsidianSides", ue.LinearColor(.019, .031, .054), .84, .20)
bevel = material("SilverBevel", ue.LinearColor(.24, .32, .45), .78, .22)
panel = material("Panel", ue.LinearColor(.010, .014, .022), .45, .28)
back = material("Room", ue.LinearColor(.0015, .002, .004), .2, .45)
edge = material("Edge", ue.LinearColor(.041, .080, .117), .7, .20)
active = material("ActiveLine", ue.LinearColor(.027, .040, .061), emissive=True)
font = ue.load_asset("/Engine/EngineFonts/DroidSansMono")
cube = ue.load_asset("/Engine/BasicShapes/Cube")
text_count = 0

def box(name, y, z, width, height, depth=8, x=18, mat=panel):
    actor = actors.spawn_actor_from_class(ue.StaticMeshActor, ue.Vector(x, y, z))
    actor.set_actor_label("NOCTURNE_" + name)
    mesh = actor.get_component_by_class(ue.StaticMeshComponent)
    mesh.set_static_mesh(cube)
    mesh.set_material(0, mat)
    actor.set_actor_scale3d(ue.Vector(depth / 100, width / 100, height / 100))
    return actor

def text(content, y, z, size=21, kind="plain", x=-8, depth=3.6, name="Text"):
    global text_count
    actor = actors.spawn_actor_from_class(ue.Text3DActor, ue.Vector(x, y, z))
    text_count += 1
    actor.set_actor_label("NOCTURNE_%s_%03d" % (name, text_count))
    component = actor.get_component_by_class(ue.Text3DComponent)
    component.set_editor_property("use_blocking_build", True)
    component.set_editor_property("font", font)
    component.set_font_size(size)
    component.set_extrude(depth)
    component.set_bevel(.32)
    component.set_bevel_segments(4)
    component.set_front_material(front[kind])
    component.set_extrude_material(side)
    component.set_bevel_material(bevel)
    component.set_back_material(side)
    component.set_editor_property("text", content)
    return actor

# The full requested composition, in a dark physical studio.
box("Room_Back", 0, 425, 2200, 1350, 20, 90, back)
box("Editor", -238, 432, 932, 710)
box("Inspector", 478, 514, 462, 546)
box("Stdin", 359, 151, 223, 174)
box("Stdout", 597, 151, 223, 174)
box("Toolbar", 0, 825, 1428, 42)
box("Console", -238, 14, 932, 103)
box("Bottomline", 0, -67, 1428, 24)
box("Editor_Edge", 235, 375, 1.5, 826, 3, 8, edge)
box("Inspector_Edge", 478, 241, 461, 1.5, 3, 8, edge)
box("IO_Edge", 478, 151, 1.5, 174, 3, 8, edge)
box("Active_Line", -238, 377, 914, 33, 2, 6, active)
box("Active_Marker", -702, 377, 3, 33, 2, -1, front["variable"])

text("NOCTURNE", -682, 817, 16, "plain", depth=1.5)
text("RUN    <    >     DEBUG / BASIC", -470, 817, 14, "variable", depth=1.5)
text("ARM64 / x86", 270, 817, 14, "comment", depth=1.5)
text("01 / VOLUME", 534, 817, 14, "comment", depth=1.5)
text("sum.cpp", -665, 752, 17, "plain", depth=1.5)
text("C++ 20     /     spatial code study", -390, 752, 13, "comment", depth=1.5)

# Each span is a real extruded mesh with the original Xcode category color.
lines = [
    [("#include", "preprocessor"), (" <iostream>", "string")],
    [("#include", "preprocessor"), (" <vector>", "string")],
    [],
    [("// A quiet place for complex ideas.", "comment")],
    [("int", "keyword"), (" ", "plain"), ("main", "declaration"), ("() {", "plain")],
    [("    std::", "plain"), ("vector", "type"), ("<", "plain"), ("int", "keyword"), ("> ", "plain"), ("values", "variable"), (" = {", "plain"), ("8, 3, 5, 2, 9", "number"), ("};", "plain")],
    [("    int", "keyword"), (" ", "plain"), ("sum", "variable"), (" = ", "plain"), ("0", "number"), (";", "plain")],
    [],
    [("    for", "keyword"), (" (", "plain"), ("int", "keyword"), (" ", "plain"), ("i", "variable"), (" = ", "plain"), ("0", "number"), ("; ", "plain"), ("i", "variable"), (" < ", "plain"), ("5", "number"), ("; ++", "plain"), ("i", "variable"), (") {", "plain")],
    [("        ", "plain"), ("sum", "variable"), (" += ", "plain"), ("values", "variable"), ("[", "plain"), ("i", "variable"), ("];", "plain")],
    [("    }", "plain")],
    [],
    [("    std::", "plain"), ("cout", "variable"), (" << ", "plain"), ("sum", "variable"), (" << ", "plain"), ("'\\n'", "string"), (";", "plain")],
    [("    return", "keyword"), (" ", "plain"), ("0", "number"), (";", "plain")],
    [("}", "plain")],
]
for index, spans in enumerate(lines):
    z = 681 - index * 34
    text(str(index + 1).rjust(2), -674, z, 16, "comment", depth=1)
    column = 0
    for content, kind in spans:
        if content.strip():
            text(content, -610 + column * 12.6, z, 21, kind)
        column += len(content)

text("VARIABLES", 278, 751, 15, "comment", depth=1)
text("main()  /  local scope", 278, 711, 14, "plain", depth=1)
text("sum", 280, 630, 20, "variable")
text("11", 550, 616, 46, "number", depth=6)
text("int", 282, 600, 13, "comment", depth=1)
text("i", 280, 536, 20, "variable")
text("2", 574, 527, 36, "number", depth=6)
text("values", 280, 457, 20, "variable")
text("std::vector<int>  /  5", 280, 420, 13, "comment", depth=1)
for idx, value in enumerate([8, 3, 5, 2, 9]):
    y = 310 + idx * 75
    box("Cell_" + str(idx), y, 347, 65, 75, 10, 8, active if idx == 2 else panel)
    text(str(value), y - 13, 343, 29, "number", x=-15, depth=5)
    text(str(idx), y - 5, 291, 12, "comment", depth=1)
text("STDIN", 280, 201, 13, "comment", depth=1)
text("STDOUT", 516, 201, 13, "comment", depth=1)
text("5", 280, 150, 20, "plain")
text("8 3 5 2 9", 280, 119, 18, "plain")
text("(pending)", 516, 150, 15, "comment")
text("CONSOLE   /   ctrl + `", -674, 40, 13, "comment", depth=1)
text("$ clang++ sum.cpp -std=c++20 -g", -674, 1, 16, "variable", depth=1)
text("ready", -674, -32, 13, "comment", depth=1)
text("VISUAL STUDY   /   REAL TEXT3D GEOMETRY", -674, -73, 11, "comment", depth=1)
text("XCODE DEFAULT DARK", 487, -73, 11, "comment", depth=1)

def light(name, position, intensity, rgb, width, height):
    actor = actors.spawn_actor_from_class(ue.RectLight, ue.Vector(*position))
    actor.set_actor_label("NOCTURNE_" + name)
    actor.set_actor_rotation(ue.MathLibrary.find_look_at_rotation(ue.Vector(*position), ue.Vector(0, 0, 420)), False)
    component = actor.get_component_by_class(ue.RectLightComponent)
    component.set_intensity(intensity)
    component.set_light_color(ue.LinearColor(*rgb))
    component.set_editor_property("source_width", width)
    component.set_editor_property("source_height", height)
    component.set_editor_property("attenuation_radius", 4000)

light("Key_Softbox", (-650, -600, 1100), 45000, (.50, .68, 1), 1100, 400)
light("Rose_Rim", (-250, 850, 450), 26000, (1, .40, .58), 550, 900)
light("Top_Silver", (-200, 0, 1250), 20000, (.8, .9, 1), 1400, 200)
camera = actors.spawn_actor_from_class(ue.CineCameraActor, ue.Vector(-1970, -110, 540))
camera.set_actor_label("NOCTURNE_Camera")
camera.set_actor_rotation(ue.MathLibrary.find_look_at_rotation(camera.get_actor_location(), ue.Vector(0, 0, 390)), False)
cine = camera.get_cine_camera_component()
cine.set_editor_property("current_focal_length", 40)
cine.set_editor_property("current_aperture", 11)
filmback = cine.get_editor_property("filmback")
filmback.sensor_width = 36
filmback.sensor_height = 22.5
cine.set_editor_property("filmback", filmback)
focus = cine.get_editor_property("focus_settings")
focus.manual_focus_distance = 1980
cine.set_editor_property("focus_settings", focus)
ue.get_editor_subsystem(ue.UnrealEditorSubsystem).set_level_viewport_camera_info(camera.get_actor_location(), camera.get_actor_rotation())
levels.save_current_level()
ue.EditorAssetLibrary.save_directory(ASSETS, only_if_is_dirty=False, recursive=True)
report = {"map": MAP, "text_actors": text_count, "geometry": "Text3D extrusion + 4-segment bevel", "palette_source": "src/xcode-palette.json / dark.raw", "camera": camera.get_actor_label(), "engine": ue.SystemLibrary.get_engine_version(), "rendered": False}
(ROOT / "build-report.json").write_text(json.dumps(report, indent=2))
print("NOCTURNE_SCENE_SAVED " + json.dumps(report))
