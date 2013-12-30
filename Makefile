DC=dmd
RM=rm -f

all: rcon

rcon: rcon.d
	$(DC) -of$@ $^

clean:
	$(RM) rcon *.o

.PHONY: clean all