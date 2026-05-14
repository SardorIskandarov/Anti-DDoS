# Anti-DDoS — minimal runner
#
#   make run    # start engine + collector + dashboard in background
#               # (keeps running after you close the terminal)
#   make kill   # stop all 3
#
# All C + Python output goes to ./monitor.log
#   tail -f monitor.log

PROJECT_ROOT  := $(shell pwd)
VENV_PY       := $(PROJECT_ROOT)/ddos_monitor/venv/bin/python3
SVC_JSON_SRC  := $(PROJECT_ROOT)/service_registry/services.json
SVC_JSON_RUN  := /tmp/svc.json
ENGINE_BIN    := $(PROJECT_ROOT)/build/l2fwd
SOCKET_PATH   := /tmp/ddos_stats_socket

MONITOR_LOG   := $(PROJECT_ROOT)/monitor.log

LOG_DIR             := /tmp
COLLECTOR_PIDFILE   := $(LOG_DIR)/anti-ddos-collector.pid
DASHBOARD_PIDFILE   := $(LOG_DIR)/anti-ddos-dashboard.pid
ENGINE_PIDFILE      := $(LOG_DIR)/anti-ddos-engine.pid

SHELL := /bin/bash

.PHONY: run kill

run:
	@echo "Anti-DDoS — starting full stack in background ..."
	@sudo -v
	@echo "Pre-flight cleanup ..."
	@sudo pkill -9 -f '[l]2fwd' 2>/dev/null || true
	@pkill -9 -f '[d]dos_monitor/main.py' 2>/dev/null || true
	@pkill -9 -f '[d]dos_monitor/web.py' 2>/dev/null || true
	@STALE=$$(sudo lsof -t -i:5000 2>/dev/null); if [ -n "$$STALE" ]; then sudo kill -9 $$STALE 2>/dev/null || true; fi
	@sleep 2
	@sudo rm -f $(SOCKET_PATH)
	@cp $(SVC_JSON_SRC) $(SVC_JSON_RUN)
	@sudo rm -f $(MONITOR_LOG)
	@: > $(MONITOR_LOG)
	@echo "[1/3] collector ..."
	@setsid nohup $(VENV_PY) -u $(PROJECT_ROOT)/ddos_monitor/main.py \
		>> $(MONITOR_LOG) 2>&1 < /dev/null & \
		echo $$! > $(COLLECTOR_PIDFILE)
	@sleep 3
	@if [ -S $(SOCKET_PATH) ]; then \
		echo "      ✓ collector (pid $$(cat $(COLLECTOR_PIDFILE)))"; \
	else \
		echo "      ✗ collector failed — see $(MONITOR_LOG)"; \
		tail -20 $(MONITOR_LOG); exit 1; \
	fi
	@echo "[2/3] dashboard ..."
	@setsid nohup $(VENV_PY) -u $(PROJECT_ROOT)/ddos_monitor/web.py \
		>> $(MONITOR_LOG) 2>&1 < /dev/null & \
		echo $$! > $(DASHBOARD_PIDFILE)
	@sleep 3
	@if grep -q "Address already in use" $(MONITOR_LOG); then \
		echo "      ✗ dashboard could not bind :5000 — port held by another process"; \
		echo "        (is the old systemd dashboard still running? see $(MONITOR_LOG))"; \
		exit 1; \
	fi
	@PID=$$(pgrep -f '[d]dos_monitor/web.py' | head -1); \
	CODE=$$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:5000/api/health 2>/dev/null || echo "000"); \
	if [ -n "$$PID" ] && { [ "$$CODE" = "200" ] || [ "$$CODE" = "503" ]; }; then \
		echo "      ✓ dashboard on :5000 (pid $$PID)"; \
	else \
		echo "      ✗ dashboard failed (HTTP $$CODE) — see $(MONITOR_LOG)"; \
		tail -20 $(MONITOR_LOG); exit 1; \
	fi
	@echo "[3/3] engine ..."
	@sudo bash -c "setsid nohup stdbuf -oL -eL $(ENGINE_BIN) -l 0-1 -n 4 -- -q 1 -p 0x3 -P --no-mac-updating --services-json=$(SVC_JSON_RUN) >> $(MONITOR_LOG) 2>&1 < /dev/null & echo \$$! > $(ENGINE_PIDFILE)"
	@sleep 4
	@if pgrep -f l2fwd > /dev/null; then \
		echo "      ✓ engine (pid $$(sudo cat $(ENGINE_PIDFILE)))"; \
	else \
		echo "      ✗ engine failed — see $(MONITOR_LOG)"; \
		sudo tail -30 $(MONITOR_LOG); exit 1; \
	fi
	@echo ""
	@echo "All 3 running in background. Dashboard: http://localhost:5000/"
	@echo "Logs:      tail -f $(MONITOR_LOG)"
	@echo "Stop with: make kill"

kill:
	@echo "Stopping all Anti-DDoS processes ..."
	@-if [ -f $(ENGINE_PIDFILE) ]; then \
		sudo kill -TERM $$(sudo cat $(ENGINE_PIDFILE)) 2>/dev/null; \
		sudo rm -f $(ENGINE_PIDFILE); \
	fi
	@-sudo pkill -9 -f '[l]2fwd' 2>/dev/null
	@-if [ -f $(DASHBOARD_PIDFILE) ]; then \
		kill -TERM $$(cat $(DASHBOARD_PIDFILE)) 2>/dev/null; \
		rm -f $(DASHBOARD_PIDFILE); \
	fi
	@-pkill -9 -f '[d]dos_monitor/web.py' 2>/dev/null
	@-if [ -f $(COLLECTOR_PIDFILE) ]; then \
		kill -TERM $$(cat $(COLLECTOR_PIDFILE)) 2>/dev/null; \
		rm -f $(COLLECTOR_PIDFILE); \
	fi
	@-pkill -9 -f '[d]dos_monitor/main.py' 2>/dev/null
	@sleep 2
	@echo "✓ All stopped."
