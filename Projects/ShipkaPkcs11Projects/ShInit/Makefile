INCLUDE = -I/usr/include/libshpkcs11 
INCLUDE += -I../include/
CXXFLAGS = $(INCLUDE)
CXXFLAGS += -g
LIBS = -ldl -lpthread

all: main

main: main_file.o low_layer_func.o cmd_functions.o Init_y_Format.o tests.o
	g++ main_file.o low_layer_func.o cmd_functions.o Init_y_Format.o tests.o $(LIBS) -o main

main_file.o: main_file.cpp
	g++ $(CXXFLAGS) -c main_file.cpp

low_layer_func.o: low_layer_func.cpp
	g++ $(CXXFLAGS) -c low_layer_func.cpp

cmd_functions.o: cmd_functions.cpp
	g++ $(CXXFLAGS) -c cmd_functions.cpp

Init_y_Format.o: Init_y_Format.cpp
	g++ $(CXXFLAGS) -c Init_y_Format.cpp

tests.o: tests.cpp
	g++ $(CXXFLAGS) -c tests.cpp

clean:
	rm -rf *.o main
