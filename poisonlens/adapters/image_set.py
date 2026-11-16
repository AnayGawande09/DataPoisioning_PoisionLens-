"""Image datasets inside an archive/folder.

Layouts, in priority order: COCO JSON, Pascal VOC XML, YOLO txt, a ``labels.csv``-style
manifest, folder-per-class (split folders such as ``train/`` are recognized), unlabeled.
For detection formats the image-level label is the class of the **largest** object.

Every image is opened with Pillow under ``limits.parse.max_image_pixels`` (decompression
bombs raise), ``verify()``-ed, then re-opened to read its size; ``load`` also decodes the
pixels. Unreadable images are skipped and reported. SVG is never opened (spec: rejected).
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any

import yaml
from defusedxml import ElementTree as DET

from poisonlens.adapters.base import DatasetAdapter, LoadResult, Source, member_ext, split_from_path
from poisonlens.adapters.fileset import RecordRow, profile_from_rows, write_rows
from poisonlens.adapters.layouts import find_manifest, folder_labels
from poisonlens.adapters.table_base import merge_selection
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import DatasetProfile, Modality, Selection

IMAGE_EXTS = {"png", "jpg", "jpeg", "bmp", "gif", "tif", "tiff", "webp"}
SIDE_EXTS = {"json", "xml", "txt", "csv", "tsv", "yaml", "yml", "names", "md"}
MAX_ANNOTATION_BYTES = 256 * 1024 * 1024


def verify_image(path: Path, max_pixels: int, decode: bool) -> tuple[int, int] | str:
    """Return (width, height) or an error string. Never raises for bad input."""
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = max_pixels
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(os_path(path)) as im:
                im.verify()
            with Image.open(os_path(path)) as im:
                size = im.size
                if decode:
                    im.load()
        return int(size[0]), int(size[1])
    except Image.DecompressionBombError as exc:
        return f"decompression bomb: {exc}"
    except Image.DecompressionBombWarning as exc:
        return f"image exceeds pixel limit: {exc}"
    except Exception as exc:  # noqa: BLE001 - any decoder failure means "unreadable"
        return f"{type(exc).__name__}: {exc}"


def _largest(objects: list[tuple[str, float]]) -> str | None:
    return max(objects, key=lambda o: o[1])[0] if objects else None


class ImageSetAdapter(DatasetAdapter):
    name = "image_set"
    specificity = 5

    def can_handle(self, src: Source) -> float:
        if not src.is_dir:
            return 0.0
        members = src.members()
        images = [m for m in members if member_ext(m) in IMAGE_EXTS]
        if not images:
            return 0.0
        data_like = [m for m in members if member_ext(m) not in SIDE_EXTS]
        return 0.9 if len(images) >= 0.5 * max(1, len(data_like)) else 0.3

    # ---------------------------------------------------------------- layouts

    def _json(self, src: Source, rel: str) -> Any:
        path = src.member_path(rel)
        if path.stat().st_size > MAX_ANNOTATION_BYTES:
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _match(self, images: list[str]) -> dict[str, str]:
        index: dict[str, str] = {}
        for rel in images:
            index.setdefault(rel.lower(), rel)
            index.setdefault(rel.rsplit("/", 1)[-1].lower(), rel)
        return index

    def _coco(self, src: Source, images: list[str]) -> tuple[dict[str, str | None], str] | None:
        index = self._match(images)
        for rel in src.members():
            if member_ext(rel) != "json":
                continue
            doc = self._json(src, rel)
            if not (isinstance(doc, dict) and {"images", "annotations", "categories"} <= doc.keys()):
                continue
            cats = {c.get("id"): str(c.get("name")) for c in doc["categories"] if isinstance(c, dict)}
            objs: dict[Any, list[tuple[str, float]]] = {}
            for a in doc["annotations"]:
                if not isinstance(a, dict):
                    continue
                bbox = a.get("bbox") or [0, 0, 0, 0]
                area = float(a.get("area") or (bbox[2] * bbox[3] if len(bbox) == 4 else 0))
                objs.setdefault(a.get("image_id"), []).append((cats.get(a.get("category_id"), "?"), area))
            labels: dict[str, str | None] = {}
            for img in doc["images"]:
                if not isinstance(img, dict):
                    continue
                name = str(img.get("file_name", "")).replace("\\", "/").lower()
                hit = index.get(name) or index.get(name.rsplit("/", 1)[-1])
                if hit:
                    labels[hit] = _largest(objs.get(img.get("id"), []))
            if labels:
                return labels, f"coco:{rel}"
        return None

    def _voc(self, src: Source, images: list[str]) -> tuple[dict[str, str | None], str] | None:
        index = self._match(images)
        labels: dict[str, str | None] = {}
        for rel in src.members():
            if member_ext(rel) != "xml":
                continue
            try:
                root = DET.parse(os_path(src.member_path(rel))).getroot()
            except Exception:  # noqa: BLE001, S112 - not a VOC file (or forbidden XML; F09 reports it)
                continue
            if root.tag != "annotation":
                continue
            fname = (root.findtext("filename") or "").strip().lower()
            hit = index.get(fname) or index.get(rel.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower() + ".jpg")
            if not hit:
                stem = rel.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
                hit = next((v for k, v in index.items() if k.rsplit(".", 1)[0] == stem), None)
            if not hit:
                continue
            objs = []
            for obj in root.findall("object"):
                name = (obj.findtext("name") or "").strip()
                box = obj.find("bndbox")
                area = 0.0
                if box is not None:
                    try:
                        coords = [float(box.findtext(t) or "nan") for t in ("xmin", "ymin", "xmax", "ymax")]
                        area = max(0.0, (coords[2] - coords[0]) * (coords[3] - coords[1]))
                    except (TypeError, ValueError):
                        area = 0.0
                if name:
                    objs.append((name, area))
            labels[hit] = _largest(objs)
        return (labels, "voc:annotation/object/name") if labels else None

    def _yolo_names(self, src: Source) -> list[str] | None:
        for rel in src.members():
            base = rel.rsplit("/", 1)[-1].lower()
            path = src.member_path(rel)
            if base in ("classes.txt", "obj.names", "classes.names"):
                return [
                    ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()
                ]
            if base in ("data.yaml", "data.yml", "dataset.yaml"):
                doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
                names = doc.get("names") if isinstance(doc, dict) else None
                if isinstance(names, dict):
                    return [str(names[k]) for k in sorted(names)]
                if isinstance(names, list):
                    return [str(n) for n in names]
        return None

    def _yolo(self, src: Source, images: list[str]) -> tuple[dict[str, str | None], str] | None:
        txt: dict[str, str] = {}
        for rel in src.members():
            if member_ext(rel) == "txt":
                stem = rel.rsplit("/", 1)[-1][:-4].lower()
                txt.setdefault(stem, rel)
        names = self._yolo_names(src)
        labels: dict[str, str | None] = {}
        matched = 0
        for img in images:
            stem = img.rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
            label_file = txt.get(stem)
            if label_file is None:
                continue
            objs = []
            valid = True
            for line in src.member_path(label_file).read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if not parts:
                    continue
                try:
                    cls = int(parts[0])
                    w, h = float(parts[3]), float(parts[4])
                except (ValueError, IndexError):
                    valid = False
                    break
                objs.append((names[cls] if names and 0 <= cls < len(names) else str(cls), w * h))
            if not valid:
                continue
            matched += 1
            labels[img] = _largest(objs)
        if matched >= max(1, len(images) // 2):
            return labels, "yolo:labels/*.txt"
        return None

    def _labels(self, src: Source, images: list[str], cfg: ScanConfig) -> tuple[dict[str, str | None], str, str]:
        for finder in (self._coco, self._voc, self._yolo):
            found = finder(src, images)
            if found:
                labels, source = found
                return labels, source, f"{source.split(':', 1)[0].upper()} annotations (largest object per image)"
        manifest = find_manifest(src, images, cfg)
        if manifest:
            labels, member, col = manifest
            return labels, f"{member}:{col}", f"manifest {member}, column '{col}'"
        labels, ok = folder_labels(images)
        if ok:
            return labels, "folder", "class from parent folder name"
        return {}, "", ""

    # ---------------------------------------------------------------- API

    def _rows(
        self, src: Source, cfg: ScanConfig, verify: int | None, decode: bool
    ) -> tuple[list[RecordRow], str, str, list[str]]:
        members = src.members()
        images = [m for m in members if member_ext(m) in IMAGE_EXTS]
        warn = []
        svgs = [m for m in members if member_ext(m) == "svg"]
        if svgs:
            warn.append(f"{len(svgs)} SVG file(s) skipped: SVG is rejected by default")
        if not images:
            raise UnsupportedFormatError("no images found")
        labels, label_source, reason = self._labels(src, images, cfg)
        rows: list[RecordRow] = []
        bad = 0
        for i, rel in enumerate(images):
            w = h = None
            if verify is None or i < verify:
                res = verify_image(src.member_path(rel), cfg.limits.parse.max_image_pixels, decode)
                if isinstance(res, str):
                    bad += 1
                    if len(warn) < 50:
                        warn.append(f"skipped {rel}: {res}")
                    continue
                w, h = res
            rows.append(
                RecordRow(
                    source_file=src.ref(rel),
                    payload_ref=src.ref(rel),
                    label_raw=labels.get(rel),
                    split=split_from_path(rel),
                    width=w,
                    height=h,
                )
            )
        if bad:
            warn.insert(0, f"{bad} unreadable image(s) skipped")
        return rows, label_source, reason, warn

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        rows, label_source, reason, warn = self._rows(src, cfg, cfg.inspect.image_verify_sample, decode=False)
        n_total = len(rows)
        return profile_from_rows(
            rows,
            n_records=n_total,
            fmt="image_set",
            adapter=self.name,
            modality=Modality.IMAGE,
            label_source=label_source or None,
            label_reason=reason,
            cfg=cfg,
            selection=merge_selection(Selection(), selection),
            warnings=warn,
            sampled=n_total > cfg.inspect.image_verify_sample,
        )

    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        rows, _source, _reason, warn = self._rows(src, cfg, None, decode=True)
        result = write_rows(canonical, rows)
        result.warnings = warn
        return result
