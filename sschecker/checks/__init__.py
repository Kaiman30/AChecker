from . import (analysis, artifacts, eventlogs, filesearch, memory, minecraft, network, registry, services,  # noqa
               system, usn)

# Порядок важен: system/services наполняют общие данные (процессы, PID служб, загрузка ПК),
# filesearch находит папки модов для minecraft, analysis сводит все следы запусков.
PIPELINE = [
    ("Система и процессы", system.run_check),
    ("Службы", services.run_check),
    ("Реестр", registry.run_check),
    ("Журналы событий", eventlogs.run_check),
    ("Файловые артефакты (Prefetch, PCA, Recent, корзина, задачи)", artifacts.run_check),
    ("USN-журнал", usn.run_check),
    ("Память процессов (методики System Informer)", memory.run_check),
    ("Поиск файлов на дисках", filesearch.run_check),
    ("Minecraft: моды, логи, профили", minecraft.run_check),
    ("Сеть", network.run_check),
    ("Сводный анализ запусков и подписей", analysis.run_check),
]
