all: wireview

wireview: wireview.cpp
	g++ -lpcap wireview.cpp -o wireview

clean:
	rm -f wireview