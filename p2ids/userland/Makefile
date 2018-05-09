.PHONY: Program.cs

all: run

intrusion_monitor.exe: Program.cs
    mcs Program.cs

clean:
    rm -f Program.exe

run: intrusion_monitor.exe
    mono intrusion_monitor.exe
