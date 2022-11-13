all: wireview

wireview: wireview.cpp
	g++ wireview.cpp -o wireview -lpcap

clean:
	rm -f wireview