#----------------------------------------
SRC_DIR := ../../samples/sample-0001
INC_DIR := ../../samples/sample-0001
OBJ_DIR := ../obj/sample-linux-x86_64-0001
TARGET_DIR := ../bin
#----------------------------------------
SRC_CPP := $(wildcard $(addsuffix /*.cpp, $(SRC_DIR)))
SRC_C   := $(wildcard $(addsuffix /*.c,   $(SRC_DIR)))
TARGET   = sample-linux-x86_64-0001
#----------------------------------------
CPPFLAGS = -std=gnu++17
CFLAGS   = -std=gnu17
LFLAGS   = -lpthread -ldl
#----------------------------------------
$(info ========== MAKE INFORMATION ==========)
$(info * SRC: $(SRC_DIR))
$(info * SRC(.cpp): $(SRC_CPP))
$(info * SRC(.c): $(SRC_C))
$(info * INC(.h): $(INC_DIR))
$(info * OBJ(.obj): $(OBJ_DIR))
$(info * OUTPUT: $(TARGET_DIR)/$(TARGET))
$(info ======================================)
#----------------------------------------
all: make_dir $(addsuffix .o, $(SRC_CPP) $(SRC_C))
	@g++ -o $(TARGET_DIR)/$(TARGET) $(OBJ_DIR)/*.o $(LFLAGS) && { \
		echo "========================================"; \
		echo "             BUILD RESULT"; \
		echo "========================================"; \
		echo "[O] BUILD SUCCEEDED"; \
		echo "   • COMMAND : g++ -o $(TARGET_DIR)/$(TARGET) $(OBJ_DIR)/*.o $(LFLAGS)"; \
		echo "   • OUTPUT  : $(TARGET_DIR)/$(TARGET)"; \
		echo "   • OBJECTS : $(OBJ_DIR)/*.o"; \
		echo "========================================"; \
	} || { \
		echo "========================================"; \
		echo "             BUILD RESULT"; \
		echo "========================================"; \
		echo "[X] BUILD FAILED"; \
		echo "   • COMMAND : g++ -o $(TARGET_DIR)/$(TARGET) $(OBJ_DIR)/*.o $(LFLAGS)"; \
		echo "========================================"; \
	}
#----------------------------------------
make_dir:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(TARGET_DIR)
#----------------------------------------
%.cpp.o:
	g++ -c $(basename $@) $(addprefix -I, $(INC_DIR)) $(CPPFLAGS) -g3 -O0 -o $(OBJ_DIR)/$(notdir $@)

%.c.o:
	gcc -c $(basename $@) $(addprefix -I, $(INC_DIR)) $(CFLAGS) -g3 -O0 -o $(OBJ_DIR)/$(notdir $@)
#----------------------------------------
clean:
	$(info ============ MAKE - CLEAN ============)
	$(info ======================================)
	@rm -f $(OBJ_DIR)/*
	@rm -f $(TARGET_DIR)/$(TARGET)
#----------------------------------------