from core.schemas import SurfaceResult
from core.surface_protocol import ensure_surface_ids, surface_id


def test_surface_id_preserves_chinese_title():
    assert surface_id(1, "外部环境变量未校验导致注入风险") == "surface_01_外部环境变量未校验导致注入风险"


def test_surface_id_replaces_only_illegal_path_characters():
    assert surface_id(2, 'Credential: secret/ref?*') == "surface_02_Credential_ secret_ref_"


def test_ensure_surface_ids_uses_path_safe_surface_label():
    results = ensure_surface_ids(
        [
            SurfaceResult(
                id="ignored",
                title="中文标题/带非法字符",
                description="demo",
                risk_type="Data Exfiltration",
                level="High",
            )
        ]
    )

    assert results[0].id == "surface_01_中文标题_带非法字符"
