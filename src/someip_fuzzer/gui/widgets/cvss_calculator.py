"""CVSS 3.1 Base Score 计算器控件。

8 个向量下拉框，实时计算分值。
公式参考：https://www.first.org/cvss/calculator/3.1
"""

from __future__ import annotations

import math
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

# ── CVSS 3.1 权重表 ────────────────────────────────────────────────────────────
_AV  = {"Network (N)": 0.85, "Adjacent (A)": 0.62, "Local (L)": 0.55, "Physical (P)": 0.20}
_AC  = {"Low (L)": 0.77, "High (H)": 0.44}
_PR  = {"None (N)": 0.85, "Low (L)": 0.62, "High (H)": 0.27}
_PR_CHANGED = {"None (N)": 0.85, "Low (L)": 0.68, "High (H)": 0.50}
_UI  = {"None (N)": 0.85, "Required (R)": 0.62}
_S   = {"Unchanged (U)": "U", "Changed (C)": "C"}
_CIA = {"High (H)": 0.56, "Low (L)": 0.22, "None (N)": 0.00}

_ABBR = {
    "Network (N)": "N", "Adjacent (A)": "A", "Local (L)": "L", "Physical (P)": "P",
    "Low (L)": "L", "High (H)": "H", "None (N)": "N",
    "Required (R)": "R", "Unchanged (U)": "U", "Changed (C)": "C",
}

def _level(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"


def compute_cvss31(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> float:
    """计算 CVSS 3.1 Base Score（0.0–10.0）。"""
    scope_changed = s == "Changed (C)"
    av_v = _AV[av]
    ac_v = _AC[ac]
    pr_v = (_PR_CHANGED if scope_changed else _PR)[pr]
    ui_v = _UI[ui]
    c_v  = _CIA[c]
    i_v  = _CIA[i]
    a_v  = _CIA[a]

    iss = 1 - (1 - c_v) * (1 - i_v) * (1 - a_v)

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av_v * ac_v * pr_v * ui_v

    if impact <= 0:
        return 0.0

    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10)
    else:
        raw = min(impact + exploitability, 10)

    return math.ceil(raw * 10) / 10


def build_vector_string(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> str:
    parts = [
        f"AV:{_ABBR[av]}", f"AC:{_ABBR[ac]}", f"PR:{_ABBR[pr]}", f"UI:{_ABBR[ui]}",
        f"S:{_ABBR[s]}", f"C:{_ABBR[c]}", f"I:{_ABBR[i]}", f"A:{_ABBR[a]}",
    ]
    return "CVSS:3.1/" + "/".join(parts)


class CvssCalculatorWidget(QWidget):
    """CVSS 3.1 Base Score 计算器。

    信号 score_changed(float, str) 在分值变化时发出（score, vector_string）。
    """

    score_changed = pyqtSignal(float, str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._combos: dict[str, QComboBox] = {}
        self._build_ui()
        self._recalculate()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        grp = QGroupBox("CVSS 3.1 计算器")
        form = QFormLayout(grp)
        form.setSpacing(4)

        vectors = [
            ("Attack Vector (AV)", list(_AV.keys())),
            ("Attack Complexity (AC)", list(_AC.keys())),
            ("Privileges Required (PR)", list(_PR.keys())),
            ("User Interaction (UI)", list(_UI.keys())),
            ("Scope (S)", list(_S.keys())),
            ("Confidentiality (C)", list(_CIA.keys())),
            ("Integrity (I)", list(_CIA.keys())),
            ("Availability (A)", list(_CIA.keys())),
        ]
        for label, options in vectors:
            cmb = QComboBox()
            cmb.addItems(options)
            cmb.currentIndexChanged.connect(self._recalculate)
            key = label.split("(")[0].strip()
            self._combos[key] = cmb
            form.addRow(label + ":", cmb)

        outer.addWidget(grp)

        # 结果行
        result_row = QHBoxLayout()
        result_row.addWidget(QLabel("Base Score:"))
        self.lbl_score = QLabel("0.0")
        self.lbl_score.setStyleSheet("font-size: 18pt; font-weight: bold; color: #89b4fa;")
        result_row.addWidget(self.lbl_score)
        self.lbl_level = QLabel("NONE")
        self.lbl_level.setStyleSheet("font-weight: bold; color: #a6adc8;")
        result_row.addWidget(self.lbl_level)
        result_row.addStretch()
        outer.addLayout(result_row)

        self.lbl_vector = QLabel("")
        self.lbl_vector.setStyleSheet("font-size: 9pt; color: #a6adc8;")
        self.lbl_vector.setWordWrap(True)
        outer.addWidget(self.lbl_vector)

    def _recalculate(self) -> None:
        try:
            av  = self._combos["Attack Vector"].currentText()
            ac  = self._combos["Attack Complexity"].currentText()
            pr  = self._combos["Privileges Required"].currentText()
            ui  = self._combos["User Interaction"].currentText()
            s   = self._combos["Scope"].currentText()
            c   = self._combos["Confidentiality"].currentText()
            i   = self._combos["Integrity"].currentText()
            a   = self._combos["Availability"].currentText()
        except (KeyError, RuntimeError):
            return

        score = compute_cvss31(av, ac, pr, ui, s, c, i, a)
        vector = build_vector_string(av, ac, pr, ui, s, c, i, a)
        level = _level(score)

        color = {"CRITICAL": "#f38ba8", "HIGH": "#fab387",
                 "MEDIUM": "#f9e2af", "LOW": "#a6e3a1", "NONE": "#a6adc8"}[level]
        self.lbl_score.setText(f"{score:.1f}")
        self.lbl_score.setStyleSheet(f"font-size: 18pt; font-weight: bold; color: {color};")
        self.lbl_level.setText(level)
        self.lbl_level.setStyleSheet(f"font-weight: bold; color: {color};")
        self.lbl_vector.setText(vector)
        self.score_changed.emit(score, vector)

    def get_score(self) -> float:
        try:
            return float(self.lbl_score.text())
        except ValueError:
            return 0.0

    def get_vector_string(self) -> str:
        return self.lbl_vector.text()

    def set_score_from_record(self, cvss_score: float) -> None:
        """按已有 CVSS 分值反向选择最接近的向量组合（简单启发式）。"""
        # 高危以上默认 Network/Low/None/None/Unchanged/High/High/High
        if cvss_score >= 9.0:
            presets = {"Attack Vector": "Network (N)", "Attack Complexity": "Low (L)",
                       "Privileges Required": "None (N)", "User Interaction": "None (N)",
                       "Scope": "Unchanged (U)", "Confidentiality": "High (H)",
                       "Integrity": "High (H)", "Availability": "High (H)"}
        elif cvss_score >= 7.0:
            presets = {"Attack Vector": "Network (N)", "Attack Complexity": "Low (L)",
                       "Privileges Required": "None (N)", "User Interaction": "None (N)",
                       "Scope": "Unchanged (U)", "Confidentiality": "High (H)",
                       "Integrity": "None (N)", "Availability": "High (H)"}
        else:
            return  # 分值较低时不预设，让用户手动选

        for key, val in presets.items():
            cmb = self._combos.get(key)
            if cmb:
                idx = cmb.findText(val)
                if idx >= 0:
                    cmb.setCurrentIndex(idx)
