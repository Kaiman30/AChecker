"""База знаний SS, перенесённая из заметок папки SS в виде данных.

Каждый блок снабжён ссылкой на исходную статью, чтобы в отчёте было видно,
на каком правиле основана находка.
"""
import re

# ---------------------------------------------------------------------------
# Инструменты для ручной перепроверки (ссылки из базы)
# ---------------------------------------------------------------------------
TOOLS = {
    "System Informer": "https://systeminformer.sourceforge.io/canary",
    "Everything 1.5a": "https://www.voidtools.com/everything-1.5a/",
    "JournalTrace": "https://github.com/ponei/JournalTrace/releases",
    "WinPrefetchView": "https://www.nirsoft.net/utils/win_prefetch_view.html",
    "PrefetchView++": "https://github.com/Orbdiff/PrefetchView/releases/tag/v1.5.3",
    "LastActivityView": "https://www.nirsoft.net/utils/computer_activity_view.html",
    "CachedProgramList": "https://github.com/ponei/CachedProgramsList/releases/tag/1.1",
    "AmcacheParser": "https://download.ericzimmermanstools.com/net9/AmcacheParser.zip",
    "AppCompatCacheParser": "https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip",
    "JumpList Explorer": "https://download.ericzimmermanstools.com/net9/JumpListExplorer.zip",
    "bstrings": "https://download.ericzimmermanstools.com/net9/bstrings.zip",
    "Registry Explorer": "https://ericzimmerman.github.io/#!index.md",
    "ShellBagAnalyzer": "https://privazer.com/ru/download-shellbag-analyzer-shellbag-cleaner.php",
    "DiE": "https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip",
    "BinText": "https://www.majorgeeks.com/files/details/bintext.html",
    "Jarabel": "https://github.com/nay-cat/Jarabel",
    "Recaf": "https://recaf.coley.software/home.html",
    "Luyten": "https://github.com/deathmarine/Luyten/releases/tag/v0.5.4_Rebuilt_with_Latest_depenencies",
    "BytecodeViewer": "https://github.com/Konloch/bytecode-viewer/releases/tag/v2.13.1",
    "VMAware": "https://github.com/kernelwernel/VMAware/releases/tag/v2.5.0",
    "FTK Imager": "https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe",
    "Autoruns": "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
    "RedLotus TaskSentinel": "https://github.com/ItzIceHere/RedLotus-Task-Sentinel/releases/download/RL/RedLotusTaskSentinel.exe",
    "Network Scanner": "https://github.com/Kaiman30/NetworkScanner/releases",
    "BAM Parser (RedLotus)": "https://raw.githubusercontent.com/PureIntent/ScreenShare/main/RedLotusBam.ps1",
    "DoomsDayFinder": "https://raw.githubusercontent.com/zedoonvm1/powershell-scripts/refs/heads/main/DoomsDayDetector.ps1",
    "JarParser": "https://raw.githubusercontent.com/NoDiff-del/JARParser/refs/heads/main/JARParser.ps1",
    "ModAnalyzer": "https://raw.githubusercontent.com/HadronCollision/PowershellScripts/refs/heads/main/HabibiModAnalyzer.ps1",
    "Services.ps1": "https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Services.ps1",
    "Signatures.ps1": "https://raw.githubusercontent.com/spokwn/powershells/refs/heads/main/signatures.ps1",
    "Faker Detection": "https://raw.githubusercontent.com/praiselily/WeHateFakers/refs/heads/main/HotspotLogs.ps1",
    "Alt Detector": "https://raw.githubusercontent.com/Enr1c0o/Powershell-Scripts/refs/heads/main/Alt-Detector.ps1",
    "Event Viewer": "eventvwr.msc",
    "VirusTotal": "https://www.virustotal.com/",
}

# ---------------------------------------------------------------------------
# Ключевые слова (Everything 1.5a → «Size by Name» + Обходы + Моды)
# ---------------------------------------------------------------------------
# Сильные: названия чит-клиентов/лоадеров и утилит очистки. Ищутся подстрокой.
CHEAT_STRONG = [
    "wurst", "bleachhack", "aristois", "huzuni", "skillclient", "liquidbounce", "nursultan",
    "calestial", "celka", "neverhook", "wexside", "wildclient", "akrien", "dreampool",
    "konas", "richclient", "rusherhack", "thunderhack", "moonhack", "doomsday", "nightware",
    "extazyy", "troxill", "dauntiblyat", "rename_me_please", "takker", "fuzeclient",
    "wisefolder", "usboblivion", "hachclient", "exloader", "forgehax", "meteor-client",
    "meteorclient", "killaura", "aimassist", "autoclicker", "triggerbot", "slinky",
    "vape_lite", "vapelite", "vapev4", "topkautobuy", "topkaautobuy", "sacurachorusfind",
    "elytrahack", "aimbot", "spambot", "spam_bot", "deadcode", "norules", "fluger",
    "flauncher", "editme", "celestialclient", "nurik",
]
# Средние: моды/функции, запрещённые на большинстве серверов, или неоднозначные клиенты.
CHEAT_MEDIUM = [
    "celestial", "expensive", "minced", "baritone", "freecam", "hitbox",
    "mob_hitbox", "autoattack", "entity_outliner", "invmove", "inventory_walk",
    "player_highlighter", "bedrock_breaker_mode", "double_hotbar", "elytra_swap",
    "armor_hotswap", "smart_moving", "savesearcher", "librarian_trade_finder", "tweakeroo",
    "clientcommands", "control-tweaks", "swingthroughgrass", "cutthrough", "diamondsim",
    "cleancut", "viaversion", "viabackwards", "viarewind", "viafabric", "viaforge",
    "viaproxy", "vialoader", "viamcp", "antileak", "arbuz", "vape", "ocmc",
    "shellbag_analyzer_cleaner", "privazer", "ricardo", "haruka",
]
# Слабые: обычные слова, которые одновременно являются названиями читов.
# Срабатывают только на целое слово в имени исполняемого файла/архива/мода.
CHEAT_WEAK = [
    "impact", "ares", "sigma", "meteor", "excellent", "future", "jessica", "delta", "venus",
    "inertia", "blade", "feather", "newlauncher", "chest", "jigsaw",
]
# Только для имён модов: вне папки mods эти слова дают ложные срабатывания (xray.exe — VPN-ядро Xray-core)
CHEAT_MOD_ONLY = ["xray", "x-ray", "orefinder", "ore_finder", "cavefinder"]
# Расширения конфигов читов (Size by Name: .akr, .wex)
CHEAT_EXTENSIONS = [".akr", ".wex"]

# Строки, которые не встречаются в честном Minecraft, но есть в читах (память javaw / классы модов)
CHEAT_MEMORY_STRINGS = [
    r"kill\s?aura", r"aimassist", r"aim\s?bot", r"auto\s?clicker", r"trigger\s?bot",
    r"anti\s?knock\s?back", r"\bnofall\b", r"\bnoslow", r"\bscaffold(?!ing)", r"\bfastplace",
    r"\bwtap\b", r"\bbhop\b", r"\bfly\s?hack", r"\bcrystal\s?aura", r"\bauto\s?crystal",
    r"\bspeedmine\b", r"\bvelocity\s?(horizontal|vertical)", r"\breach\s?:\s?[3-6]\.\d",
    r"aimassist_on", r"\bself\s?destruct",
]

# Инструменты, которыми пользуются проверяющие: их блокировка — признак обхода.
SS_TOOL_NAMES = [
    "systeminformer", "processhacker", "everything", "journaltrace", "lastactivityview",
    "winprefetchview", "prefetchview", "usbdeview", "bamparser", "amcacheparser",
    "appcompatcacheparser", "jumplistexplorer", "registryexplorer", "shellbagsexplorer",
    "timelineexplorer", "die.exe", "diel.exe", "bintext", "recaf", "luyten", "bytecode",
    "procexp", "procmon", "autoruns", "anydesk", "cachedprogramslist", "alternatestreamview",
    "userassistview", "ftk", "regedit", "taskmgr", "cmd.exe", "powershell", "eventvwr",
    "mmc.exe", "jarabel", "paths-parser", "pathsparser",
]
SS_TOOL_DOMAINS = [
    "systeminformer", "sourceforge", "voidtools", "nirsoft", "ericzimmerman",
    "github", "githubusercontent", "anydesk", "virustotal", "majorgeeks", "privazer",
    "recaf", "cloudfront", "sysinternals", "microsoft.com", "discord", "gofile",
    "mediafire", "mega.nz", "dropbox",
]

# Утилиты очистки следов (Обходы → Обнаружение чистки)
CLEANER_TOOLS = [
    "usboblivion", "shellbag_analyzer", "shellbaganalyzer", "privazer", "ccleaner",
    "bleachbit", "wise registry", "wiseregcleaner", "glary", "eraser", "sdelete",
    "prefetch cleaner", "lastactivityview", "wisefolder", "folderhider",
]

# ---------------------------------------------------------------------------
# Точные размеры известных читов (Everything 1.5a → «Jar Sizes», «Size by Weight»)
# ---------------------------------------------------------------------------
JAR_CHEAT_SIZES = frozenset([
    2263, 5266, 6515, 6770, 6778, 7016, 7218, 7803, 7891, 9327, 10283, 10605, 10958, 11554,
    16541, 17308, 17339, 18180, 18527, 18587, 18734, 19266, 20578, 20583, 20639, 20883,
    21161, 21234, 21664, 22036, 22861, 26247, 27546, 27809, 28084, 28439, 29304, 29567,
    30279, 31549, 31607, 34449, 34669, 35971, 35993, 38149, 39017, 39321, 40142, 42782,
    47159, 48242, 50828, 51212, 52426, 54088, 59381, 62782, 65316, 65486, 65765, 66659,
    67491, 68794, 69757, 72334, 74105, 80751, 88896, 95530, 98811, 100523, 100799, 101297,
    101571, 101703, 102297, 102733, 103761, 104954, 105623, 105672, 112386, 120640, 138417,
    143006, 143597, 143600, 147329, 147873, 151762, 153937, 156722, 156779, 166677, 169718,
    173698, 183634, 183651, 192156, 202720, 257482, 263070, 267746, 274865, 300286, 334588,
    343169, 350629, 409616, 410358, 517248, 519731, 532826, 539151, 556494, 597406, 636621,
    640838, 878781, 925493, 1077149, 1165063, 1181556, 1444714, 1471429, 1569093, 1822841,
    3113569, 3425801, 3541075, 3541138, 3642292, 3684385, 4642998, 5630483, 7052171,
    7059952, 22258750, 25704986, 26179274, 26691896,
])
FILE_CHEAT_SIZES = frozenset([
    22885, 23810, 43883, 110439, 111866, 114974, 116689, 132133, 138351, 140200, 147329,
    202720, 274865, 460288, 479296, 514855, 1488896, 1499136, 1562249, 1613824, 1672329,
    1677449, 1680521, 1819289, 1820884, 1883602, 1897269, 1961742, 1968128, 2023236,
    2108662, 2258533, 2305645, 2363704, 2372788, 2373676, 2545664, 3684385, 3697285,
    3711166, 3712014, 4413440, 5007380, 5143837, 5524900, 5641728, 5918208, 5934592,
    6229504, 6244043, 6533121, 6573056, 6867367, 6944256, 7187456, 7204864, 7788032,
    7969792, 7988736, 8011776, 8249687, 9332326, 9400174, 9530356, 9951744, 10071288,
    10657176, 15076480, 15438336, 15445581, 16629226, 16836288, 16855568, 16964112,
    18764384, 19521024, 24390144, 24536064, 25158656, 28107997, 31445308, 88065933,
    197933122, 355527744,
])
# Vec.dll: size:30720 + строки net/minecraft/client/entity/player/ClientPlayerEntity | AxisAlignedBB
VEC_DLL_SIZE = 30720
VEC_DLL_MARKERS = [b"net/minecraft/client/entity/player/ClientPlayerEntity",
                   b"net/minecraft/util/math/AxisAlignedBB"]
# Doomsday: ext:jar size:21kb-10mb content:"l.png" content:"mcmod.info"
DOOMSDAY_SIZE_RANGE = (21 * 1024, 10 * 1024 * 1024)

# ---------------------------------------------------------------------------
# Вес легитимных модов (Моды → Вес модификаций), КБ
# ---------------------------------------------------------------------------
_MOD_WEIGHTS_RAW = """
BetterFps:18,62|FpsReducer:42|FoamFix:58|FPSPlus:147|MemoryFix:12|ArmorStatusHUD:25,26,27,29
Batty's Coordinates PLUS Mod for Forge:245|BattysCoordinatesPLUS:19|BattyCordinates:18,19
BetterHudPvP:566|BetterPvPMod:368|CheatBreakerHUD:27,33,35,36,101|ChromaHUD:95
ComboDisplayMod:14|CoordinatesMOD:31|CoordsMod:11|DirectionHUD:23,24|FPSDisplayMod:7
InGameInfoXML:293|ItemCounter Mod:26|LevelHead:49|Sk1er LevelHead:78
Powns ArmorStatus HUD:44,47|Powns PotionEffect HUD:51|Ping Display Mod:9|ReachDisplayMod:10
StatusEffectHUD:23,24,26|StatusEffectsHUD:26|Sidebar Mod:10,12|SidebarMod:12
Sidebar Mod Revamp:18|ToroHealth:47|Custom Crosshair Mod:32,64|FovControl:7|HitRangeMod:14
Keystrokes Reach:13|Keystrokes mod:11|Keystroke Mod:13,14|KeystrokesMod:10,11,14,19,36,64,81,90
KeyMod:59,60|MouseDelayFix:5|Perspective Mod:32|Perspective Mod fix:32|PerspectiveMod:11
Ping Tag Mod:23|QuickSW:4|Spinner CPS Mod:47|ToggleSneak:20,21,24,30|ToggleSneak LabyMod:78
ToggleSneak ToggleSprint:21|Powns ToggleSneak Edit:31,33|MotionBlur Mod:7|FastChat:4,5
HypixelAutocomplete:13|NameHistory:14|NoCloseMyChat:10|TabbyChat:379,380|ToggleChat:74,112
ChatTriggers:210|EraseChatMod:3|AnimatedCrosshair:152|ChunkAnimator:17|Clearglass Mod:8
CustomCursorMod:29,32|CustomSkyMod:41388|GlintColorizer:16|ItemPhysic Mod-Lite:31
ItemPhysicLite:31|ItemPhysicModLite:31|Nametag Mod:9|OldAnimationsMod:49,1435,1437,2209
OldAnimationsMod Classloader:72|OldAnimationsModClassloader:72|ParticleMod:6|Physical Items:36,48
ShinyPots:5|SmoothFont:214|WingsMod:23|AimBow:27|AltLoader:33|AutoFriend:14|AutoGG:12
AutoLogin:69|AutoWho:4|autotip:57,59|BadlionPingDisplayMod:9|BetterSprinting:65|BetterSprint:70
BiomesOPlenty:5652|BlockOverlay:17,18|Blood Kill Effect Mod:9|BLSquadMod:802
BspkrsCore:62,63,193,194,195|bspkrsCore universal:193,194|Canalex3Keystrokes:25
CanelexKeystrokes:24|Cleaner:13|ComeCloser:12|CoroUtil:1100|CrosshairMod:68
CursorIconChanger:5|DabMod:9|DefaultOptions:34|Ding:5|FastCraft:34,114,115,177,178
FastCraft Mod:115|FastRecraft:3|FastRecraft Mod:3|FoxLib:69|FPSSpoofer:10|FullscreenWindowed:18
Hide Join messages:48|In-Game Account Switcher:66|Ingame-Account-Switcher-Mod:80|In-Game Account:66
IngameServerSwitcher:5|InputFix:17|Legacy Java Fixer:7|LocaleFix:2|LunatriusCore:57,77
MacroKey:39|MinecraftCapes:19|MusicPlayer:533|NameChanger:7|NickHider:1347|nostalgia:125|Of:12
OptionSync:15|Orange's Simple Mods:72|PackDisplayMod:9|PersistentBits:36|PlayerAPI:260,261,276
PlayerProfile:7|PotAlerts Mod:29|Potion Counter Mod:9|ProjectL:5|RankedProjectile:51
RealTimeTranslation:95|ReAuth:24|RedHerring:8|RenderPlayerAPI:146|ReplayMod:17279
Resourcepack24:52|ResourcePackOrganizer:41|Saturation Mod:39|SaturationMod:21|Schematica:249
Screenshot Mod:33|ScreenshotUploader:188|Settings Profile Mod:21|Shrug:19|SkinChanger:102
SmartRender:164|SoundFilters:41|Super Secret Settings Fix:4|SwitchConnectionMod:115
TcpNoDelayMod:5,6,16|TexFix:7|TimeChanger:15|TrippleFps:2|TweetCheive:1112|UTeamCore:375
Vanilla Enhancements:327|VersionChecker:123|VoxelMapNoRadar:419|5zig PvP Mod:6842|5zig Mod:4937
Pack Organizer:40
"""
_VERSION_TOKEN = re.compile(r"^(v?\d+[a-z]?|r\d+|mc|forge|fabric|universal|snapshot|fix\d*|jar|"
                            r"for|beta|alpha|release|final|lite|max)$")


def normalize_mod_name(name: str) -> str:
    name = name.lower()
    if name.endswith(".jar"):
        name = name[:-4]
    tokens = [t for t in re.split(r"[^a-z0-9']+", name) if t]
    tokens = [t for t in tokens if not _VERSION_TOKEN.match(t) and not t.isdigit()]
    return "".join(t.replace("'", "") for t in tokens)


def _parse_weights():
    out = {}
    for chunk in _MOD_WEIGHTS_RAW.replace("\n", "|").split("|"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, sizes = chunk.rsplit(":", 1)
        out.setdefault(normalize_mod_name(name), set()).update(int(s) for s in sizes.split(","))
    return out


MOD_WEIGHTS_KB = _parse_weights()
# Вес известных читов из того же списка (TcpNoDelay 1.0 (Aimbot), Vape, OCMC)
KNOWN_CHEAT_WEIGHTS = {"tcpnodelay aimbot": 7, "vape dll": 2480, "vape lite exec": 6510,
                       "ocmcclient": 13023}

# ---------------------------------------------------------------------------
# Методы/импорты, которые меняют читы (Моды → 4, 5, Примеры)
# ---------------------------------------------------------------------------
SUSPICIOUS_METHODS = {
    "forge": {
        "func_174813_aQ": "getEntityBoundingBox — хитбоксы (HitBox/Reach)",
        "func_71059_n": "attackEntity — KillAura/автокликер",
        "func_70032_d": "getDistance — Aimbot",
        "func_70107_b": "setPosition — телепорт/NoFall",
        "func_70016_h": "setMotion — Speed/Fly",
        "func_70685_l": "isVisible/canEntityBeSeen — ESP/Wallhack",
        "func_175638_a": "shouldSideBeRendered — X-Ray",
        "func_174826_a": "renderEntity — ESP",
        "func_226277_ct_": "getPosX — Aimbot",
        "func_226281_cx_": "getPosZ — Aimbot",
        "field_72338_b": "AxisAlignedBB.minY",
        "field_72337_e": "AxisAlignedBB.maxY",
    },
    "fabric": {
        "method_5829": "getBoundingBox — хитбоксы",
        "method_6105": "attack — KillAura",
        "method_5739": "distanceTo — Aimbot",
        "method_5810": "setPosition — телепорт/NoFall",
        "method_5818": "setVelocity — Speed/Fly",
        "method_5779": "canSee — ESP",
        "method_23317": "getX", "method_23321": "getZ", "method_5857": "setBoundingBox",
        "class_238": "Box (хитбокс)",
    },
}
SUSPICIOUS_IMPORTS = {
    "net/minecraft/util/math/AxisAlignedBB": "Forge: хитбоксы",
    "org/spongepowered/asm/mixin/injection": "Fabric/Mixin: внедрение кода",
    "net/labymod/api/event": "LabyMod: события рендера",
    "C03PacketPlayer": "Пакеты движения (NoFall/Speed)",
    "RenderWorldLastEvent": "Рендер поверх мира (ESP)",
}

# ---------------------------------------------------------------------------
# Службы (База → 7. Службы, Обходы → Threads)
# ---------------------------------------------------------------------------
SERVICES = [
    # имя, описание, ключевой поток (Threads), критичность при отключении
    ("SysMain", "Регистрирует Prefetch (.pf)", "sechost.dll", "HIGH"),
    ("PcaSvc", "Program Compatibility Assistant — следы разовых запусков .exe/.jar", "pcasvc.dll", "HIGH"),
    ("DPS", "Diagnostic Policy Service — фиксирует подозрительные .exe и подмену файлов", "dps.dll", "HIGH"),
    ("EventLog", "Журналы событий Windows", "wevtsvc.dll", "CRITICAL"),
    ("DiagTrack", "Телеметрия — иногда фиксирует запуск редких .exe", None, "MEDIUM"),
    ("DusmSvc", "Учёт сетевого трафика приложений", "wlanapi.dll", "MEDIUM"),
    ("Appinfo", "Запуск с повышенными правами (UAC)", None, "MEDIUM"),
    ("bam", "Background Activity Moderator — время запусков .exe", None, "HIGH"),
    ("CDPUserSvc", "Connected Devices Platform (ActivitiesCache)", "ucrtbase.dll", "LOW"),
    ("WSearch", "Индексация (SearchIndexer)", None, "LOW"),
    ("Dnscache", "DNS-кэш (домены, к которым обращались программы)", None, "LOW"),
    ("Schedule", "Планировщик задач", None, "LOW"),
    ("BFE", "Base Filtering Engine (брандмауэр)", None, "LOW"),
]

# ---------------------------------------------------------------------------
# Сеть (База → 8. Сеть). mode: exists — «бан за имеющееся значение»
# ---------------------------------------------------------------------------
TCPIP = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
NETWORK_TWEAKS = [
    # (ключ HKLM, параметр, режим, ожидаемое/условие, критичность, описание, статья)
    (TCPIP, "GlobalMaxTcpWindowSize", "exists", None, "HIGH",
     "Ограничение окна TCP — сервер постоянно ждёт ACK (фейк-лаги)", "Размер окна TCP"),
    (TCPIP, "TcpMaxDataRetransmissions", "exists", None, "HIGH",
     "Долгие повторные отправки — можно «висеть» в лаге без вылета", "Packet Loss Abuse"),
    (TCPIP, "SackOpts", "eq", 0, "HIGH",
     "Отключён Selective ACK — при потере пакета пересылается вся пачка", "Packet Loss Abuse"),
    (TCPIP, "EnablePMTUDiscovery", "exists", None, "HIGH",
     "Отключение Path MTU Discovery — пакеты по 576 байт, рост пинга", "Фрагментация и MTU"),
    (TCPIP, "EnablePMTUBHDetect", "exists", None, "HIGH",
     "Black Hole detection — пакеты пропадают", "Фрагментация и MTU"),
    (TCPIP, "DisableTaskOffload", "eq", 1, "LOW",
     "Все сетевые расчёты перенесены на CPU", "Global Task Offload"),
    (TCPIP, "DefaultTTL", "eq", 64, "LOW", "Изменён TTL (дефолт 128)", "TTL"),
    (TCPIP, "EnableWsd", "eq", 0, "LOW", "Запрет сброса тюнинга TCP", "Windows Scaling Heuristics"),
    (TCPIP, "Tcp1323Opts", "exists", None, "LOW", "Изменены расширения TCP", "Windows Scaling Heuristics"),
    (r"SYSTEM\CurrentControlSet\Services\AFD\Parameters", "FastSendDatagramThreshold", "exists",
     None, "HIGH", "Буферизация UDP-дейтаграмм", "Ускорение UDP"),
    (r"SOFTWARE\Policies\Microsoft\Windows\Psched", "NonBestEffortLimit", "exists", None, "MEDIUM",
     "Урезание полосы через QoS", "Qos Bandwidth Limit"),
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
     "NetworkThrottlingIndex", "lt", 10, "MEDIUM",
     "Троттлинг сетевых пакетов (значение < 10 → очередь и микро-фризы)", "Системный троттлинг"),
    (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
     "SystemResponsiveness", "eq", 100, "MEDIUM",
     "100% приоритета фоновым задачам", "Системный троттлинг"),
]
# Параметры интерфейсов: Tcpip\Parameters\Interfaces\{ID} — «бан за имеющееся значение»
INTERFACE_TWEAKS = [
    ("TCPNoDelay", "Nagle — пакеты копятся в буфере, для врага игрок «дёргается»"),
    ("TcpAckFrequency", "Сколько пакетов ждать перед отправкой ACK"),
    ("TcpDelAckTicks", "Таймер задержки ACK"),
]
NIC_CLASS = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
NIC_TWEAKS = [
    ("*NdisDeviceType", "eq", 1, "MEDIUM", "Карта скрыта как «съёмная»"),
    ("*LsoV2IPv4", "eq", 1, "LOW", "Large Send Offload (джиттер управления). Часто включён драйвером по умолчанию"),
    ("*InterruptModeration", "eq", 1, "INFO", "Группировка прерываний. Часто включена драйвером по умолчанию"),
    ("ScanValidInterval", "exists", None, "LOW", "Интервал сканирования Wi-Fi изменён"),
]

# ---------------------------------------------------------------------------
# Команды, которые ищут в MsMpEng / PowerShell / истории (System Informer → MsMpEng, wmic)
# ---------------------------------------------------------------------------
SUSPICIOUS_COMMANDS = [
    (r"fsutil\s+usn\s+deletejournal", "CRITICAL", "Удаление USN-журнала"),
    (r"wevtutil(\.exe)?\s+(cl|clear-log)", "CRITICAL", "Очистка журнала событий"),
    (r"clear-eventlog", "CRITICAL", "Очистка журнала событий (PowerShell)"),
    (r"remove-module\s+psreadline", "HIGH", "Отключение записи истории PowerShell"),
    (r"set-psreadlineoption.+historysavestyle", "HIGH", "Отключение записи истории PowerShell"),
    (r"reg(\.exe)?\s+delete", "HIGH", "Удаление ключей реестра"),
    (r"remove-item(property)?\s+.*(hklm|hkcu|registry::)", "HIGH", "Удаление ключей реестра (PowerShell)"),
    (r"\bsc(\.exe)?\s+(stop|config)\s+\w+", "HIGH", "Остановка/перенастройка службы"),
    (r"(stop|set)-service", "HIGH", "Остановка/перенастройка службы (PowerShell)"),
    (r"\.lastwritetime\s*=|\.creationtime\s*=|\.lastaccesstime\s*=", "HIGH", "Подмена дат файла (Data-Modified)"),
    (r"attrib(\.exe)?\s+[+-][rhs]", "MEDIUM", "Изменение атрибутов файлов"),
    (r"wmic(\.exe)?\s+process\s+call\s+create", "HIGH", "Запуск через WMIC (обход Prefetch/расширений)"),
    (r"java(w)?(\.exe)?\s+.*-jar", "MEDIUM", "Запуск .jar из консоли"),
    (r"-javaagent", "HIGH", "Подключение java-агента (инжект)"),
    (r"rundll32(\.exe)?\s+", "MEDIUM", "Запуск DLL через rundll32"),
    (r"regsvr32(\.exe)?\s+", "MEDIUM", "Регистрация/запуск DLL через regsvr32"),
    (r"copy\s+/b", "HIGH", "Склейка файлов (стеганография)"),
    (r"\breg(\.exe)?\s+add", "MEDIUM", "Изменение реестра из консоли"),
    (r"taskkill", "LOW", "Принудительное завершение процессов"),
    (r"curl(\.exe)?\s+.*-o", "LOW", "Скачивание файла через curl"),
    (r"(invoke-webrequest|iwr|invoke-restmethod|irm)\s+", "LOW", "Скачивание через PowerShell"),
    (r"bitsadmin", "MEDIUM", "Скачивание через BITS"),
    (r"-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}", "HIGH", "Закодированная команда PowerShell"),
    (r"vssadmin\s+delete", "HIGH", "Удаление теневых копий"),
    (r"cipher\s+/w", "HIGH", "Затирание свободного места"),
    (r"winrm|enable-psremoting", "MEDIUM", "Удалённое управление PowerShell (WinRM)"),
    (r"usboblivion", "CRITICAL", "Очистка следов USB"),
]

# ---------------------------------------------------------------------------
# Регулярки System Informer (System Informer → regexes)
# ---------------------------------------------------------------------------
RE_DPS_ENTRY = re.compile(r"!!(?P<name>[^!]{3,260}?)!(?P<ts>\d{4}/\d{2}/\d{2}:\d{2}:\d{2}:\d{2})!")
RE_DEVICE_PATH = re.compile(r"\\device\\harddiskvolume\d+\\[^\x00\"<>|*?\r\n]+", re.I)
RE_DOS_PATH = re.compile(r"(?:\\\\\?\\)?[A-Za-z]:\\[^\x00\"<>|*?\r\n:]{2,300}", re.I)
RE_FILE_URL = re.compile(r"file:///[A-Za-z]:/[^\x00\"<>|*?\r\n]{2,300}", re.I)
RE_ADS = re.compile(r"(?i)([a-z]:\\[^:<>\"|?*\r\n]+\.\w{2,4}):([^:\s\\\]]+)")
RE_JNATIVE = re.compile(r"JNativeHook[^\x00\s\"]*\.dll", re.I)
RE_CDP_APP = re.compile(r"\{\"application\":\"(?P<app>[^\"]+)\"", re.I)
RE_BFE_QUERY = re.compile(r"(TCP|UDP) Query User\{[^}]*\}[^\x00]{0,300}", re.I)
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:gg|ru|su|cc|xyz|club|"
                       r"pro|net|com|org|io|me|fun|top|site|online|store|shop|dev|app|lol|wtf|"
                       r"tk|ml|ga|cf|cloud|host|space|tech|win|best|vip|today)\b", re.I)

# Расширения, которые ожидаются у реально исполняемых файлов
EXEC_EXTS = {".exe", ".com", ".scr", ".cpl", ".msc", ".bat", ".cmd", ".msi", ".pif"}
# Файлы, в которых не должно быть исполняемого кода/архивов (стеганография, смена расширения)
MEDIA_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".txt", ".log", ".mp3",
              ".mp4", ".avi", ".mkv", ".mov", ".wav", ".pdf", ".doc", ".docx", ".ini", ".cfg",
              ".json", ".xml", ".css", ".html", ".htm", ".sys", ".dat", ".tmp"}
STEGO_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".mp4", ".avi", ".mp3", ".txt", ".wav",
              ".webp", ".mkv", ".mov"}
INTERESTING_EXTS = {".exe", ".jar", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".py", ".ahk",
                    ".zip", ".rar", ".7z", ".pf", ".sys", ".msi", ".scr", ".com", ".lnk"}

# Безопасные альтернативные потоки NTFS
BENIGN_ADS = {"zone.identifier", "smartscreen", "com.dropbox.attributes", "com.dropbox.attrs",
              "afp_afpinfo", "afp_resource", "encryptable", "favicon", "ms-properties",
              "oecustomproperty", "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}", "katvirtualdrive",
              "wofcompresseddata", "$kernel.purge.esbcache", "$kernel.purge.apprxblob"}

# Известные папки для расшифровки UserAssist
KNOWN_FOLDER_GUIDS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "%SystemRoot%\\System32",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "%ProgramFiles%",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "%ProgramFiles(x86)%",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "%SystemRoot%",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "%SystemRoot%\\SysWOW64",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "%AppData%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "%AppData%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
    "{374DE290-123F-4565-9164-39C4925E467B}": "%UserProfile%\\Downloads",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "%UserProfile%\\Desktop",
    "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "%UserProfile%\\Documents",
}

# Каталоги лаунчеров Minecraft (относительно %APPDATA% / %USERPROFILE%)
MC_DIRS_APPDATA = [".minecraft", ".tlauncher", ".feather", "PrismLauncher\\instances",
                   "PolyMC\\instances", "MultiMC\\instances", "ModrinthApp\\profiles",
                   "com.modrinth.theseus\\profiles", "gdlauncher_next\\instances",
                   "GDLauncher\\instances", ".technic\\modpacks", "ATLauncher\\instances",
                   ".lunarclient", "Badlion Client", ".labymod", "LabyMod"]
MC_DIRS_PROFILE = [".lunarclient", "curseforge\\minecraft\\Instances", ".minecraft",
                   "AppData\\Roaming\\.minecraft"]

# Цели Prefetch, по которым ищут следы очистки (Артефакты → Prefetch)
CLEANUP_BINARIES = {
    "FSUTIL.EXE": ("CRITICAL", "fsutil — возможна очистка USN-журнала"),
    "WEVTUTIL.EXE": ("CRITICAL", "wevtutil — возможна очистка журналов событий"),
    "REG.EXE": ("MEDIUM", "reg.exe — манипуляции с реестром"),
    "WMIC.EXE": ("MEDIUM", "wmic — возможен запуск файла без расширения (wmic process call create)"),
    "RUNDLL32.EXE": ("LOW", "rundll32 — запуск DLL (в т.ч. с изменённым расширением)"),
    "REGSVR32.EXE": ("LOW", "regsvr32 — запуск DLL"),
    "USBOBLIVION.EXE": ("CRITICAL", "USBOblivion — очистка следов USB"),
    "USBOBLIVION32.EXE": ("CRITICAL", "USBOblivion — очистка следов USB"),
    "USBOBLIVION64.EXE": ("CRITICAL", "USBOblivion — очистка следов USB"),
    "SHELLBAG_ANALYZER_CLEANER.EXE": ("HIGH", "ShellBag Analyzer Cleaner — очистка ShellBags"),
    "VSSADMIN.EXE": ("MEDIUM", "vssadmin — работа с теневыми копиями"),
    "CIPHER.EXE": ("MEDIUM", "cipher — возможно затирание свободного места"),
    "SDELETE.EXE": ("HIGH", "SDelete — безвозвратное удаление файлов"),
    "SDELETE64.EXE": ("HIGH", "SDelete — безвозвратное удаление файлов"),
    "BITSADMIN.EXE": ("LOW", "bitsadmin — скачивание файлов без браузера"),
}
