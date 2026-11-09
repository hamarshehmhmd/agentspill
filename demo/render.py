"""Render the agentspill narrated demo: real command output + edge-tts narration.

Usage: python demo/render.py   (needs ffmpeg, edge-tts, Pillow, network)
"""
import asyncio
import os
import re
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(HERE, "build")
OUT = os.path.join(ROOT, "demo.mp4")
SDKBIN = "/tmp/asvenv/bin"
SANDBOX = "/tmp/asdemo"
W, H, FPS = 1280, 720, 24
VOICE = "en-US-AndrewNeural"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BG, FG = (24, 26, 33), (220, 223, 228)
ANSI = {"31": (255, 95, 95), "32": (95, 215, 120), "33": (240, 200, 80),
        "2": (130, 135, 145), "36": (90, 200, 230), "35": (200, 140, 230), "1": FG}
PROMPT = "dev@laptop ~/shop-api $ "

SCENES = [
    {
        "kind": "title",
        "title": "agentspill",
        "sub": "your coding agent saved your password.\nthen it committed it.",
        "say": "This is agent spill, a small open source command line tool for a new kind of secret leak: "
               "credentials that coding agents like Claude Code, Cursor and Codex write to disk on their own.",
    },
    {
        "kind": "bullets",
        "title": "The problem",
        "bullets": [
            "\"Don't ask again\" saves the exact command, password included",
            "   to .claude/settings.local.json, ignored only by a global gitignore",
            "1,122 public copies with secrets on GitHub (Apiiro, Nov 2026)",
            "MCP configs are meant to be committed; 12% of key slots hardcoded",
            "Most are shapeless: DSN passwords, Bearer headers, -p flags",
        ],
        "say": "When you approve a command in Claude Code with don't ask again, the exact command, password "
               "included, is saved as a permission rule inside your project. That file is only ignored by your "
               "global git ignore, so a clone on another machine commits it. Researchers just found over a thousand "
               "public copies. M C P configs are meant to be committed, and most of these secrets have no vendor "
               "token shape, so regular secret scanners never see them.",
    },
    {
        "kind": "term",
        "cmds": ["agentspill --color always scan"],
        "say": "Here is a demo repo with fake secrets. agent spill scan knows where each agent writes: permission "
               "rules, M C P configs, memory files and saved chats. It finds a Supabase service role key, a GitHub token, a Postgres password inside a "
               "connection string, Bearer headers, and passwords inside approved commands. And for each one it tells "
               "you if it is committed, or ignored only by your global git ignore.",
    },
    {
        "kind": "term",
        "cmds": ["gitleaks git . --no-banner 2>&1 | tail -1",
                 "agentspill scan --history | tail -2 | head -1"],
        "say": "For comparison, gitleaks scans the same history and finds two leaks: the token shaped ones. "
               "agent spill finds seven distinct secrets, six of them shapeless. It doesn't replace gitleaks, "
               "it covers what gitleaks can't see.",
    },
    {
        "kind": "term",
        "cmds": ["agentspill scan --history --format checklist | cut -c1-118"],
        "say": "With history, it reads every committed version of every agent file on all branches, and flags "
               "commits co-authored by the agent. Here a my sequel password was committed, then deleted, and it is "
               "still in history. The checklist puts rotation first, with where to rotate each one, because "
               "deleting a file does not un-leak a secret.",
    },
    {
        "kind": "term",
        "cmds": ["agentspill fix --write | cut -c1-118", "git status --short && agentspill scan | tail -2"],
        "say": "agent spill fix is a dry run by default. With write, it removes the permission rules that contain "
               "secrets, rewrites M C P configs to use each agent's own variable syntax, moves the values to a "
               "private env file, and adds the local only files to the repo's git ignore. The memory file it leaves "
               "for you to edit by hand.",
    },
    {
        "kind": "term",
        "cmds": ["agentspill home --home-dir ../demo-home | cut -c1-118",
                 "agentspill home --home-dir ../demo-home --scrub --write --skip-recent 0 | head -3"],
        "say": "agent spill home checks the stores outside git: the Claude dot json file, session transcripts, "
               "prompt history and Codex config. Scrub redacts secrets from transcripts and history, and leaves live "
               "configs alone.",
    },
    {
        "kind": "term",
        "cmds": ["agentspill install-hook",
                 "git add -f .claude/settings.local.json && git commit -qm wip; echo exit=$?"],
        "say": "Finally, a pre commit hook, also available for the pre commit framework and as a GitHub Action, "
               "blocks local only agent files and new secrets before they are committed.",
    },
    {
        "kind": "bullets",
        "title": "Limits",
        "bullets": [
            "Pattern + context rules: rotate, don't trust a clean run blindly",
            "Doesn't verify keys against providers (no network calls)",
            "Forks and other people's clones: rotation is the only fix",
            "Agents add new on-disk stores; the file list needs updates",
        ],
        "say": "The limits. It uses patterns and context, so it can miss things or be wrong. It never calls "
               "providers to check if a key is live. It can't clean forks or other clones, so rotation is the real "
               "fix. And agents keep adding new places they write to.",
    },
    {
        "kind": "bullets",
        "title": "Try it",
        "bullets": [
            "curl -fsSL https://raw.githubusercontent.com/",
            "   hamarshehmhmd/agentspill/main/install.sh | sh",
            "agentspill scan --history   ·   agentspill home",
            "github.com/hamarshehmhmd/agentspill",
            "GNU AGPL-3.0-or-later (commercial licenses available)",
        ],
        "say": "Install it with the one line installer and run agent spill scan with history. It has no "
               "dependencies, and it's licensed under the GNU Affero General Public License version 3 or later, with "
               "commercial licenses available from the author. It's on GitHub at hamarsheh m h m d slash agent spill.",
    },
]


async def tts(text, path):
    import edge_tts
    for attempt in range(8):
        try:
            await edge_tts.Communicate(text, VOICE, rate="+4%").save(path)
            return
        except Exception:
            if os.path.exists(path):
                os.remove(path)
            if attempt == 7:
                raise
            await asyncio.sleep(5)


def duration(path):
    out = subprocess.check_output(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path],
        text=True,
    )
    return float(out.strip())


EXPORTS = {}


def run_cmd(cmd, cwd):
    if cmd.startswith("export ") and "=" in cmd:
        k, v = cmd[7:].split("=", 1)
        EXPORTS[k] = v
        return ""
    env = dict(os.environ, FORCE_COLOR="1", **EXPORTS)
    env.pop("NO_COLOR", None)
    env["PATH"] = SDKBIN + os.pathsep + env["PATH"]
    env["COLUMNS"] = "120"
    p = subprocess.run(
        ["bash", "-c", "shopt -s nullglob; " + cmd],
        cwd=cwd, capture_output=True, text=True, env=env,
    )
    return (p.stdout + p.stderr).rstrip("\n")


def parse_ansi(line):
    spans, color, bold = [], FG, False
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        m = re.match(r"\x1b\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    color, bold = FG, False
                elif code == "1":
                    bold = True
                elif code in ANSI:
                    color = ANSI[code]
        elif part:
            spans.append((part, color, bold))
    return spans


class Term:
    def __init__(self):
        self.font = ImageFont.truetype(MONO, 14)
        self.bold = ImageFont.truetype(MONO_B, 14)
        self.cw = self.font.getlength("M")
        self.lh = 20
        self.cols = int((W - 80) / self.cw)

    def wrap(self, spans):
        lines, cur, n = [], [], 0
        for text, c, b in spans:
            while text:
                room = self.cols - n
                if len(text) <= room:
                    cur.append((text, c, b)); n += len(text); text = ""
                else:
                    cut = text.rfind(" ", 0, room + 1)
                    cut = cut if cut > 0 else room
                    cur.append((text[:cut], c, b)); lines.append(cur); cur, n = [], 0
                    text = "    " + text[cut:].lstrip(" ")
        lines.append(cur)
        return lines

    def frame(self, lines, cursor=False):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([20, 14, W - 20, H - 14], 12, fill=(30, 33, 41), outline=(60, 64, 76))
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([40 + i * 24, 30, 54 + i * 24, 44], fill=c)
        d.text((W // 2, 37), "~/shop-api — bash", font=ImageFont.truetype(SANS, 15), fill=(150, 155, 165), anchor="mm")
        visible = lines[-30:]
        y = 64
        for ln in visible:
            x = 40
            for text, c, b in ln:
                d.text((x, y), text, font=self.bold if b else self.font, fill=c)
                x += self.cw * len(text)
            y += self.lh
        if cursor:
            last = visible[-1] if visible else []
            x = 40 + self.cw * sum(len(t) for t, _, _ in last)
            d.rectangle([x, y - self.lh + 3, x + self.cw - 2, y - 4], fill=FG)
        return img


def card(scene):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    if scene["kind"] == "title":
        d.text((W // 2, 280), scene["title"], font=ImageFont.truetype(MONO_B, 78), fill=(95, 215, 120), anchor="mm")
        d.multiline_text((W // 2, 420), scene["sub"], font=ImageFont.truetype(SANS, 32), fill=FG, anchor="mm",
                         align="center", spacing=12)
        d.text((W // 2, 620), "github.com/hamarshehmhmd/agentspill  ·  scan · --history · fix · home · hook  ·  GNU AGPL-3.0",
               font=ImageFont.truetype(SANS, 20), fill=(150, 155, 165), anchor="mm")
    else:
        d.text((90, 90), scene["title"], font=ImageFont.truetype(SANS_B, 52), fill=(95, 215, 120))
        f = ImageFont.truetype(SANS, 29)
        y = 200
        for b in scene["bullets"]:
            if b and not b.startswith("   "):
                d.text((90, y), "•", font=f, fill=(240, 200, 80))
            d.text((130, y), b.strip(), font=f, fill=FG)
            y += 58 if b.startswith("   ") or not b else 62
    return img


class Writer:
    def __init__(self, path, audio):
        self.p = subprocess.Popen(
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
             "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-", "-i", audio,
             "-af", "apad", "-c:v", "libx264", "-preset", "medium", "-crf", "23",
             "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-ar", "44100",
             "-shortest", path],
            stdin=subprocess.PIPE,
        )
        self.n = 0

    def put(self, img, count=1):
        data = img.tobytes()
        for _ in range(count):
            self.p.stdin.write(data)
        self.n += count

    def close(self):
        self.p.stdin.close()
        self.p.wait()
        if self.p.returncode:
            sys.exit("ffmpeg failed")


def _cap_output(out):
    lines = out.splitlines()
    if len(lines) > 26:
        lines = lines[:24] + ["…", lines[-1]]
    return "\n".join(lines)


def render_scene(i, scene, workdir):
    audio = os.path.join(BUILD, f"s{i}.mp3")
    if not os.path.exists(audio):
        asyncio.run(tts(scene["say"], audio))
    total = int((duration(audio) + 0.7) * FPS)
    path = os.path.join(BUILD, f"s{i}.mp4")
    w = Writer(path, audio)
    if scene["kind"] != "term":
        w.put(card(scene), total)
        w.close()
        return path
    t = Term()
    shown = scene.get("show", scene["cmds"])
    outputs = [_cap_output(run_cmd(c, workdir)) for c in scene["cmds"]]
    # If show has more lines than cmds (a command displayed as several visual lines
    # that map to one executed command), join show into one typed command per output.
    if len(shown) != len(outputs):
        if len(outputs) == 1:
            shown = [" ".join(s.rstrip("\\").strip() for s in shown)]
        elif len(shown) > len(outputs):
            # first N-1 outputs map 1:1; remaining show lines are the last command
            shown = list(shown[: len(outputs) - 1]) + [
                " ".join(s.rstrip("\\").strip() for s in shown[len(outputs) - 1 :])
            ]
    steps = list(zip(shown, outputs))
    typing = sum(len(s) for s, _ in steps) / 32 * FPS
    pause = max(6, int((total - typing) / max(1, len(steps))) - 4)
    lines = []
    for cmd, out in steps:
        prompt = [(PROMPT, (95, 215, 120), True)]
        for k in range(0, len(cmd) + 1, 2):
            frame = t.frame(lines + t.wrap(prompt + [(cmd[:k], FG, False)]), cursor=True)
            w.put(frame)
        lines += t.wrap(prompt + [(cmd, FG, False)])
        for ol in out.splitlines():
            lines += t.wrap(parse_ansi(ol))
        lines.append([])
        hold = min(pause, max(0, total - w.n))
        w.put(t.frame(lines), hold)
    final = t.frame(lines + t.wrap([(PROMPT, (95, 215, 120), True)]), cursor=True)
    if w.n < total:
        w.put(final, total - w.n)
    w.close()
    return path


def main():
    os.makedirs(BUILD, exist_ok=True)
    if os.path.exists(SANDBOX):
        shutil.rmtree(SANDBOX)
    os.makedirs(SANDBOX)
    repo = os.path.join(SANDBOX, "shop-api")
    subprocess.run([sys.executable, os.path.join(ROOT, "examples", "make_demo_repo.py"), repo], check=True)
    subprocess.run([sys.executable, os.path.join(ROOT, "examples", "make_demo_home.py"),
                    os.path.join(SANDBOX, "demo-home")], check=True)
    parts = [render_scene(i, s, repo) for i, s in enumerate(SCENES)]
    with open(os.path.join(BUILD, "list.txt"), "w") as fh:
        fh.writelines(f"file '{p}'\n" for p in parts)
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i",
         os.path.join(BUILD, "list.txt"), "-c:v", "libx264", "-crf", "23", "-pix_fmt", "yuv420p",
         "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart", OUT],
        check=True,
    )
    with open(os.path.join(BUILD, "narration.txt"), "w") as fh:
        fh.write("\n\n".join(s["say"] for s in SCENES) + "\n")
    print(OUT, round(duration(OUT), 1), "s")


if __name__ == "__main__":
    main()
