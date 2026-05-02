UV   ?= uv
HOST ?= 127.0.0.1
PORT ?= 8000

.PHONY: help install lab1 lab2 project demo1 demo2 demo-project clean

help:
	@echo "CNUCoin labs + Project Variant 4 (managed by uv)"
	@echo "  make install        — sync dependencies into .venv via uv"
	@echo "  make lab1           — run Lab 1 FastAPI server on http://$(HOST):$(PORT)"
	@echo "  make lab2           — run Lab 2 FastAPI server on http://$(HOST):$(PORT)"
	@echo "  make project        — run Project (gradebook) server on http://$(HOST):$(PORT)"
	@echo "  make demo1          — run Lab 1 console demo"
	@echo "  make demo2          — run Lab 2 PoW demo (DIFFICULTY=N to override)"
	@echo "  make demo-project   — run Project end-to-end console demo"
	@echo "  make clean          — remove SQLite DBs and __pycache__"

install:
	$(UV) sync

lab1:
	cd lab1 && $(UV) run uvicorn server:app --host $(HOST) --port $(PORT) --reload

lab2:
	cd lab2 && $(UV) run uvicorn server:app --host $(HOST) --port $(PORT) --reload

project:
	cd project && $(UV) run uvicorn server:app --host $(HOST) --port $(PORT) --reload

demo1:
	cd lab1 && $(UV) run python demo.py

demo2:
	cd lab2 && $(UV) run python demo.py

demo-project:
	cd project && $(UV) run python demo.py

clean:
	rm -f lab1/cnucoin.db lab2/cnucoin.db project/gradebook.db
	rm -rf lab1/__pycache__ lab2/__pycache__ project/__pycache__
