# ── BinHTTP project Makefile ───────────────────────────────────────────
#
#  Targets:
#    all      — build bserve and bcurl
#    bserve   — build server only
#    bcurl    — build client only
#    clean    — remove build artefacts
#    demo     — start server, run bcurl, stop server  (requires www/)

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c99 -pedantic -g
LDFLAGS =

# Windows needs winsock
ifeq ($(OS),Windows_NT)
    LDFLAGS += -lws2_32
    EXT = .exe
else
    EXT =
endif

SRCS_COMMON = frame.c
SRCS_BSERVE = bserve.c $(SRCS_COMMON)
SRCS_BCURL  = bcurl.c  $(SRCS_COMMON)

.PHONY: all clean demo

all: bserve$(EXT) bcurl$(EXT)

bserve$(EXT): $(SRCS_BSERVE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bcurl$(EXT): $(SRCS_BCURL)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f bserve$(EXT) bcurl$(EXT) *.o

# ── demo target ────────────────────────────────────────────────────────
# Creates a tiny www/ directory, starts the server in the background,
# runs bcurl with -v, then kills the server.
demo: all
	@mkdir -p www
	@echo '<html><body><h1>Hello from BinHTTP</h1></body></html>' > www/index.html
	@echo "[demo] starting bserve on port 9000 …"
	@./bserve$(EXT) ./www 9000 &
	@sleep 1
	@echo "[demo] running bcurl …"
	@./bcurl$(EXT) -v localhost:9000/index.html
	@echo "[demo] done."
	@pkill -f "bserve.*9000" 2>/dev/null || true
