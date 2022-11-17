all: wireview

wireview: wireview.cpp callback.cpp
	g++ wireview.cpp callback.cpp -o wireview -lpcap

clean:
	rm -f wireview