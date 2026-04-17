# Proyektning asosiy joylashgan manzili
PWD=$(shell pwd)

# Build everything
all: meson.build
	rm -rf build
	meson setup build
	ninja -C build

# Run Flask and l2fwd in background (No logs)
run: ./build/l2fwd
	@echo "Dasturlarni orqa fonda ishga tushirish..."
	
	# Python Flaskni orqa fonda ishga tushirish (loglarsiz)
	cd $(PWD)/ddos_monitor && sudo nohup ./venv/bin/python3 main.py > /dev/null 2>&1 &
	
	# L2fwd (DPDK) dasturini orqa fonda ishga tushirish (loglarsiz)
	sudo nohup $(PWD)/build/l2fwd -l 0-1 -n 4 -- -q 1 -p 0x3 -P --no-mac-updating > /dev/null 2>&1 &
	
	@echo "Dasturlar muvaffaqiyatli ishga tushirildi."

# Orqa fondagi barcha jarayonlarni to'xtatish
kill:
	@echo "Jarayonlar to'xtatilmoqda..."
	-sudo pkill -f l2fwd
	-sudo pkill -f main.py
	@echo "Barcha jarayonlar to'xtatildi."

# Clean up build files
clean:
	rm -rf build