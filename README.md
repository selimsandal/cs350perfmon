# Linux
```
./scheduler_monitor "chrt -o stress-ng --cpu 4 --timeout 30s" cfs_scheduler.txt
./scheduler_monitor "chrt -b stress-ng --cpu 4 --timeout 30s" batch_scheduler.txt
./scheduler_monitor "chrt -f -p 50 stress-ng --cpu 4 --timeout 30s" fifo_scheduler.txt
./scheduler_monitor "chrt -r -p 50 stress-ng --cpu 4 --timeout 30s" rr_scheduler.txt
```

# Windows / macOS / FreeBSD
`cs350perfmon.exe .\Benchmarks\geekbench\geekbench6.exe`