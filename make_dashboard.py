#!/usr/bin/env python3
r"""
Risk Dashboard Generator for the AI Phishing Email Analyzer
------------------------------------------------------------
Generates a SOC-style risk dashboard PNG (gauge + category bars)
from ANY analyzed email.

USAGE:
    python make_dashboard.py samples\phishing_sample.eml
    python make_dashboard.py samples\phishing_sample.eml --out my_dashboard.png

REQUIREMENT: matplotlib (one-time install):
    pip install matplotlib
"""
import argparse
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("matplotlib not found. Install it once with:  pip install matplotlib")

# reuse the analyzer from the main tool
from ai_phishing_analyzer import analyze, WEIGHTS

RED, GREEN, AMBER = "#f85149", "#3fb950", "#d29922"


def main():
    ap = argparse.ArgumentParser(description="Generate a risk dashboard PNG from an email analysis")
    ap.add_argument("email_file", help="Path to the .eml/.txt email file")
    ap.add_argument("--out", default=None, help="Output PNG name (default: <email>_dashboard.png)")
    args = ap.parse_args()

    try:
        result = analyze(args.email_file)
    except FileNotFoundError:
        sys.exit(f"ERROR: file not found: {args.email_file}")

    score, level = result["risk_score"], result["risk_level"]
    color = GREEN if level == "CLEAN" else (AMBER if level in ("LOW", "MEDIUM") else RED)

    cats = list(WEIGHTS.keys())
    scores = [result["category_scores"].get(c, 0) for c in cats]
    maxs = [WEIGHTS[c] for c in cats]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5.2), dpi=150,
                                   gridspec_kw={"width_ratios": [1, 1.6]})
    fig.patch.set_facecolor("#0d1117")

    # gauge
    ax1.set_facecolor("#0d1117"); ax1.axis("off")
    ax1.add_patch(plt.Circle((0.5, 0.42), 0.33, transform=ax1.transAxes,
                             facecolor="#161b22", edgecolor="#30363d", lw=2))
    ax1.add_patch(plt.Circle((0.5, 0.42), 0.26, transform=ax1.transAxes,
                             facecolor="#0d1117", edgecolor=color, lw=10))
    ax1.text(0.5, 0.46, str(score), transform=ax1.transAxes, ha="center", va="center",
             fontsize=44, color=color, weight="bold", family="monospace")
    ax1.text(0.5, 0.34, "/ 100", transform=ax1.transAxes, ha="center", fontsize=13,
             color="#8b949e", family="monospace")
    ax1.text(0.5, 0.62, level, transform=ax1.transAxes, ha="center", fontsize=14,
             color=color, weight="bold", family="monospace")
    ax1.text(0.5, 0.14, result["file"].split("/")[-1].split("\\")[-1],
             transform=ax1.transAxes, ha="center", fontsize=10, color="#58a6ff", family="monospace")

    # bars
    ax2.set_facecolor("#0d1117")
    for s in ("top", "right"):
        ax2.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax2.spines[s].set_color("#30363d")
    ax2.tick_params(colors="#8b949e", labelsize=10)
    y = list(range(len(cats)))[::-1]
    ax2.barh(y, maxs, color="#21262d", height=0.55)
    ax2.barh(y, scores, color=color, height=0.55)
    for yi, sc, mx in zip(y, scores, maxs):
        ax2.text(sc + 0.6, yi, f"{sc}/{mx}", va="center", fontsize=10,
                 color="#c9d1d9", family="monospace")
    ax2.set_yticks(y)
    ax2.set_yticklabels(cats, fontsize=10.5)
    ax2.set_xlim(0, 34)
    ax2.set_xlabel("points", color="#8b949e", fontsize=10)
    ax2.set_title("RISK BREAKDOWN - deterministic analysis", color="#c9d1d9",
                  fontsize=12, pad=12, family="monospace")

    plt.tight_layout()
    out = args.out or result["file"].rsplit(".", 1)[0] + "_dashboard.png"
    fig.savefig(out, facecolor=fig.patch.get_facecolor(), bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)
    print(f"Dashboard saved: {out}")


if __name__ == "__main__":
    main()
