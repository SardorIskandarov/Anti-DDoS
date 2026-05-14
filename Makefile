# Anti-DDoS — dev runner (SSH-friendly version)
#
# Usage:
#   make run       # start all 3 processes; primes sudo once at top
#   make stop      # kill all 3
#   make status    # show what's running
#   make logs      # tail -f all 3 logs
#   make clean     # remove log files
#
# Browsing from a remote machine (PowerShell + SSH):
#   Option A — SSH tunnel:
#     From your Windows PowerShell, BEFORE you SSH normally, run:
#       ssh -L 5000:localhost:5000 user_1@<vm-ip>
#     Then on the VM run `make run`. From PowerShell-side browser:
#       http://localhost:5000/
#
#   Option B — Direct (if firewall allows):
#     After `make run`, look at the URL it prints. From any browser:
#       http://<vm-ip>:5000/

PROJECT_ROOT  := $(shell pwd)
VENV_PY       := $(PROJECT_ROOT)/ddos_monitor/venv/bin/python3
SVC_JSON_SRC  := $(PROJECT_ROOT)/service_registry/services.json
SVC_JSON_RUN  := /tmp/svc.json
ENGINE_BIN    := $(PROJECT_ROOT)/build/l2fwd
SOCKET_PATH   := /tmp/ddos_stats_socket

LOG_DIR             := /tmp
COLLECTOR_LOG       := $(LOG_DIR)/anti-ddos-collector.log
DASHBOARD_LOG       := $(LOG_DIR)/anti-ddos-dashboard.log
ENGINE_LOG          := $(LOG_DIR)/anti-ddos-engine.log

COLLECTOR_PIDFILE   := $(LOG_DIR)/anti-ddos-collector.pid
DASHBOARD_PIDFILE   := $(LOG_DIR)/anti-ddos-dashboard.pid
ENGINE_PIDFILE      := $(LOG_DIR)/anti-ddos-engine.pid

SHELL := /bin/bash

.PHONY: run stop restart status logs logs-engine logs-collector logs-dashboard clean help

help:
	@echo "Anti-DDoS dev runner"
	@echo ""
	@echo "  make run               start engine + collector + dashboard in background"
	@echo "  make stop              kill all 3 processes"
	@echo "  make restart           stop + run"
	@echo "  make status            show what's running and ports"
	@echo "  make logs              tail -f all 3 logs"
	@echo "  make logs-engine       tail just the engine log"
	@echo "  make logs-collector    tail just the collector log"
	@echo "  make logs-dashboard    tail just the dashboard log"
	@echo "  make clean             remove old log files"
	@echo ""
	@echo "Systemd (production deployment):"
	@echo "  sudo make install-systemd     install systemd units (one-time)"
	@echo "  sudo make systemd-enable      enable auto-start on boot"
	@echo "  sudo systemctl start anti-ddos.target"
	@echo "  make systemd-status           check status of all 3 services"
	@echo "  make systemd-logs             tail journalctl for all 3"
	@echo "  make systemd-restart          restart all 3 services in order"
	@echo "  sudo make uninstall-systemd   remove systemd integration"

run:
	@echo "============================================"
	@echo "Anti-DDoS — starting full stack in background"
	@echo "============================================"
	@echo ""
	@echo "Caching sudo credentials (you'll be prompted for password once) ..."
	@sudo -v
	@echo "✓ sudo cached"
	@echo ""
	@echo "Pre-flight cleanup ..."
	@-sudo pkill -9 -f l2fwd 2>/dev/null
	@-pkill -9 -f "ddos_monitor/main.py" 2>/dev/null
	@-pkill -9 -f "ddos_monitor/web.py" 2>/dev/null
	@-STALE=$$(sudo lsof -t -i:5000 2>/dev/null); if [ -n "$$STALE" ]; then sudo kill -9 $$STALE 2>/dev/null; fi
	@sleep 2
	@sudo rm -f $(SOCKET_PATH)
	@cp $(SVC_JSON_SRC) $(SVC_JSON_RUN)
	@echo "✓ pre-flight done"
	@echo ""
	@echo "[1/3] Starting collector ..."
	@setsid nohup $(VENV_PY) $(PROJECT_ROOT)/ddos_monitor/main.py \
		> $(COLLECTOR_LOG) 2>&1 < /dev/null & \
		echo $$! > $(COLLECTOR_PIDFILE)
	@sleep 3
	@if [ -S $(SOCKET_PATH) ]; then \
		echo "      ✓ collector listening on $(SOCKET_PATH) (pid $$(cat $(COLLECTOR_PIDFILE)))"; \
	else \
		echo "      ✗ collector failed to bind socket"; \
		echo "      Check log: $(COLLECTOR_LOG)"; \
		tail -20 $(COLLECTOR_LOG); \
		exit 1; \
	fi
	@echo ""
	@echo "[2/3] Starting dashboard ..."
	@setsid nohup $(VENV_PY) $(PROJECT_ROOT)/ddos_monitor/web.py \
		> $(DASHBOARD_LOG) 2>&1 < /dev/null & \
		echo $$! > $(DASHBOARD_PIDFILE)
	@sleep 3
	@CODE=$$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://localhost:5000/api/health 2>/dev/null || echo "000"); \
	if [ "$$CODE" = "200" ] || [ "$$CODE" = "503" ]; then \
		echo "      ✓ dashboard responding on :5000 (pid $$(cat $(DASHBOARD_PIDFILE))) (HTTP $$CODE)"; \
	else \
		echo "      ✗ dashboard not responding (HTTP $$CODE)"; \
		echo "      Check log: $(DASHBOARD_LOG)"; \
		tail -20 $(DASHBOARD_LOG); \
		exit 1; \
	fi
	@echo ""
	@echo "[3/3] Starting engine (requires sudo for DPDK) ..."
	@sudo bash -c "setsid nohup $(ENGINE_BIN) -l 0-1 -n 4 -- -q 1 -p 0x3 -P --no-mac-updating --services-json=$(SVC_JSON_RUN) > $(ENGINE_LOG) 2>&1 < /dev/null & echo \$$! > $(ENGINE_PIDFILE)"
	@sleep 4
	@if pgrep -f l2fwd > /dev/null; then \
		echo "      ✓ engine running (pid $$(sudo cat $(ENGINE_PIDFILE)))"; \
	else \
		echo "      ✗ engine failed to start"; \
		echo "      Check log: $(ENGINE_LOG)"; \
		sudo tail -30 $(ENGINE_LOG); \
		exit 1; \
	fi
	@echo ""
	@echo "============================================"
	@echo "ALL 3 PROCESSES RUNNING IN BACKGROUND"
	@echo "============================================"
	@echo ""
	@echo "From this VM (local):"
	@echo "  http://localhost:5000/"
	@echo ""
	@echo "From another machine on the same network:"
	@echo "  http://$$(hostname -I | awk '{print $$1}'):5000/"
	@echo ""
	@echo "From your Windows PowerShell over SSH tunnel:"
	@echo "  Step 1 — In a NEW PowerShell window, run:"
	@echo "    ssh -L 5000:localhost:5000 user_1@$$(hostname -I | awk '{print $$1}')"
	@echo "  Step 2 — Then browse to: http://localhost:5000/"
	@echo ""
	@echo "Tail all logs:    make logs"
	@echo "Just one log:     make logs-engine | logs-collector | logs-dashboard"
	@echo "Stop everything:  make stop"
	@echo "Show status:      make status"
	@echo ""

stop:
	@echo "Stopping all Anti-DDoS processes ..."
	@-if [ -f $(ENGINE_PIDFILE) ]; then \
		sudo kill -TERM $$(sudo cat $(ENGINE_PIDFILE)) 2>/dev/null; \
		sudo rm -f $(ENGINE_PIDFILE); \
	fi
	@-sudo pkill -9 -f l2fwd 2>/dev/null
	@-if [ -f $(DASHBOARD_PIDFILE) ]; then \
		kill -TERM $$(cat $(DASHBOARD_PIDFILE)) 2>/dev/null; \
		rm -f $(DASHBOARD_PIDFILE); \
	fi
	@-pkill -9 -f "ddos_monitor/web.py" 2>/dev/null
	@-if [ -f $(COLLECTOR_PIDFILE) ]; then \
		kill -TERM $$(cat $(COLLECTOR_PIDFILE)) 2>/dev/null; \
		rm -f $(COLLECTOR_PIDFILE); \
	fi
	@-pkill -9 -f "ddos_monitor/main.py" 2>/dev/null
	@sleep 2
	@echo "✓ All stopped."

restart: stop run

status:
	@echo "============================================"
	@echo "Anti-DDoS process status"
	@echo "============================================"
	@printf "Engine    (l2fwd):       "
	@if pgrep -f l2fwd > /dev/null; then printf "RUNNING (pid %s)\n" "$$(pgrep -f l2fwd | head -1)"; else printf "stopped\n"; fi
	@printf "Collector (main.py):     "
	@if pgrep -f "ddos_monitor/main.py" > /dev/null; then printf "RUNNING (pid %s)\n" "$$(pgrep -f ddos_monitor/main.py | head -1)"; else printf "stopped\n"; fi
	@printf "Dashboard (web.py):      "
	@if pgrep -f "ddos_monitor/web.py" > /dev/null; then printf "RUNNING (pid %s)\n" "$$(pgrep -f ddos_monitor/web.py | head -1)"; else printf "stopped\n"; fi
	@echo ""
	@printf "Socket %s:   " "$(SOCKET_PATH)"
	@if [ -S $(SOCKET_PATH) ]; then printf "exists\n"; else printf "missing\n"; fi
	@printf "Port 5000:                  "
	@if sudo lsof -i:5000 -t > /dev/null 2>&1; then printf "in use (pid %s)\n" "$$(sudo lsof -t -i:5000 | head -1)"; else printf "free\n"; fi
	@echo ""
	@echo "Dashboard URL: http://localhost:5000/  (via SSH tunnel from PowerShell)"

logs:
	@echo "Tailing all 3 logs (Ctrl+C to stop tailing; processes keep running)"
	@tail -F $(COLLECTOR_LOG) $(DASHBOARD_LOG) $(ENGINE_LOG) 2>/dev/null

logs-engine:
	@sudo tail -F $(ENGINE_LOG)

logs-collector:
	@tail -F $(COLLECTOR_LOG)

logs-dashboard:
	@tail -F $(DASHBOARD_LOG)

clean: stop
	@-sudo rm -f $(COLLECTOR_LOG) $(DASHBOARD_LOG) $(ENGINE_LOG)
	@-sudo rm -f $(COLLECTOR_PIDFILE) $(DASHBOARD_PIDFILE) $(ENGINE_PIDFILE)
	@echo "✓ Logs and PID files cleaned."

# ====== systemd integration ======
SYSTEMD_DIR := $(PROJECT_ROOT)/systemd
SYSTEMD_UNITS := anti-ddos-collector.service anti-ddos-engine.service anti-ddos-dashboard.service anti-ddos-dpdk-setup.service anti-ddos.target
SYSTEMD_INSTALL_DIR := /etc/systemd/system

install-systemd:
	@echo "Installing systemd units to $(SYSTEMD_INSTALL_DIR) ..."
	@for unit in $(SYSTEMD_UNITS); do \
		sudo cp $(SYSTEMD_DIR)/$$unit $(SYSTEMD_INSTALL_DIR)/$$unit; \
		echo "  ✓ $$unit"; \
	done
	@sudo chmod +x $(SYSTEMD_DIR)/dpdk-setup.sh
	@echo "  ✓ dpdk-setup.sh marked executable"
	@sudo systemctl daemon-reload
	@echo ""
	@echo "✓ Systemd units installed."
	@echo ""
	@echo "To start the whole stack:"
	@echo "  sudo systemctl start anti-ddos.target"
	@echo ""
	@echo "To enable auto-start on boot:"
	@echo "  sudo make systemd-enable"
	@echo ""
	@echo "After enable+reboot, the full stack auto-starts."

uninstall-systemd:
	@echo "Stopping and removing systemd units ..."
	@-sudo systemctl stop anti-ddos.target 2>/dev/null
	@-sudo systemctl stop anti-ddos-engine.service 2>/dev/null
	@-sudo systemctl stop anti-ddos-collector.service 2>/dev/null
	@-sudo systemctl stop anti-ddos-dashboard.service 2>/dev/null
	@-sudo systemctl stop anti-ddos-dpdk-setup.service 2>/dev/null
	@-sudo systemctl disable anti-ddos.target 2>/dev/null
	@-sudo systemctl disable anti-ddos-engine.service 2>/dev/null
	@-sudo systemctl disable anti-ddos-collector.service 2>/dev/null
	@-sudo systemctl disable anti-ddos-dashboard.service 2>/dev/null
	@-sudo systemctl disable anti-ddos-dpdk-setup.service 2>/dev/null
	@for unit in $(SYSTEMD_UNITS); do \
		sudo rm -f $(SYSTEMD_INSTALL_DIR)/$$unit; \
		echo "  ✓ removed $$unit"; \
	done
	@sudo systemctl daemon-reload
	@echo "✓ All systemd units removed. Data preserved."

systemd-start:
	@sudo systemctl start anti-ddos.target
	@sleep 3
	@$(MAKE) systemd-status

systemd-stop:
	@sudo systemctl stop anti-ddos.target

systemd-restart:
	@sudo systemctl restart anti-ddos-collector.service
	@sleep 2
	@sudo systemctl restart anti-ddos-engine.service
	@sleep 2
	@sudo systemctl restart anti-ddos-dashboard.service

systemd-status:
	@echo "============================================"
	@echo "Anti-DDoS systemd status"
	@echo "============================================"
	@printf "Collector:  "
	@systemctl is-active anti-ddos-collector.service || true
	@printf "Engine:     "
	@systemctl is-active anti-ddos-engine.service || true
	@printf "Dashboard:  "
	@systemctl is-active anti-ddos-dashboard.service || true
	@echo ""
	@echo "Detail (most recent state lines):"
	@-systemctl --no-pager --lines=0 status anti-ddos-collector.service | head -5
	@-systemctl --no-pager --lines=0 status anti-ddos-engine.service | head -5
	@-systemctl --no-pager --lines=0 status anti-ddos-dashboard.service | head -5

systemd-logs:
	@journalctl -u anti-ddos-collector.service -u anti-ddos-engine.service -u anti-ddos-dashboard.service -f

systemd-logs-collector:
	@journalctl -u anti-ddos-collector.service -f

systemd-logs-engine:
	@journalctl -u anti-ddos-engine.service -f

systemd-logs-dashboard:
	@journalctl -u anti-ddos-dashboard.service -f

systemd-enable:
	@sudo systemctl enable anti-ddos.target
	@sudo systemctl enable anti-ddos-collector.service
	@sudo systemctl enable anti-ddos-engine.service
	@sudo systemctl enable anti-ddos-dashboard.service
	@sudo systemctl enable anti-ddos-dpdk-setup.service
	@echo "✓ Services enabled for auto-start on boot."

systemd-disable:
	@sudo systemctl disable anti-ddos.target
	@sudo systemctl disable anti-ddos-collector.service
	@sudo systemctl disable anti-ddos-engine.service
	@sudo systemctl disable anti-ddos-dashboard.service
	@sudo systemctl disable anti-ddos-dpdk-setup.service
	@echo "✓ Services disabled (will not auto-start on boot)."

.PHONY: install-systemd uninstall-systemd systemd-start systemd-stop systemd-restart \
        systemd-status systemd-logs systemd-logs-collector systemd-logs-engine \
        systemd-logs-dashboard systemd-enable systemd-disable
