# ADR 001: dedicated Linux-agent repository

Status: accepted. The Windows `panopticon-agent` is C++20 and couples its live collection
and delivery to ETW, Sysmon, Windows CNG, and WinHTTP. Adding Linux procfs/inotify/systemd
and privileged response code there would create an OS-conditioned build, release, and
security boundary. `panopticon-linux-agent` is therefore a separate repository; it shares
the Panopticon Event wire contract, not source code. A future contracts package is deferred
until more than two independent producers require generated bindings.
