# Scripts

Простые скрипты для разработки и релиза.

## dev.sh - Инструменты разработки

```bash
./scripts/dev.sh test      # Запустить тесты
./scripts/dev.sh format    # Форматировать код
./scripts/dev.sh analyze   # Анализ кода
./scripts/dev.sh check     # Всё сразу (format + analyze + test)
./scripts/dev.sh deps      # Обновить зависимости
./scripts/dev.sh changelog # Предпросмотр changelog
./scripts/dev.sh coverage  # Тесты с покрытием
```

## release.sh - Релиз пакета

```bash
./scripts/release.sh 1.0.1          # Подготовить релиз
./scripts/release.sh 1.0.1 --publish # Подготовить и опубликовать
```

Что делает:

1. Проверяет тесты, форматирование, анализ
2. Обновляет версию в pubspec.yaml
3. Создаёт git тег
4. Генерирует changelog
5. Коммитит изменения
6. Валидирует пакет
7. Публикует (если --publish)
