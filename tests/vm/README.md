# Validation VM

Every **REAL-VM VERIFIED** statement in this repository was produced on a VM built from [Vagrantfile](Vagrantfile):
Ubuntu 22.04 (`generic/ubuntu2204`), kernel 5.15.0-91, x86_64, 8 vCPU, 6 GB RAM, VirtualBox. Other kernels,
distributions and architectures are not validated.

```bash
cd tests/vm
vagrant up                                   # first boot installs the toolchain (about 10 minutes)
vagrant ssh
git clone --recurse-submodules --branch main https://github.com/Panopticon-Co/panopticon-linux-agent.git ~/src/panopticon-linux-agent
cd ~/src/panopticon-linux-agent
cmake -S . -B build-rel -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build-rel --parallel
sudo ctest --test-dir build-rel --output-on-failure -j1
```

Rules that were learned the hard way:

* **One timing-sensitive job at a time.** The soak, the performance ladder and the chaos suite compete for CPU and
  disk; running a build or `ctest` during a soak is recorded as a perturbation window in its report.
* **Never clean up by process name (`pkill panopticon-sens`) on a VM that runs a soak.** The e2e and
  chaos scripts track the pids they start; a name-based kill would take down the soak's sensor.
* Detached long jobs: `setsid -f bash script.sh </dev/null >/dev/null 2>&1`, then poll their log. A `vagrant ssh`
  command is limited by your terminal's timeout, not by the VM.
* If you copy the tree into the VM instead of cloning it, exclude only the **top-level** build directories (`tar --exclude=./build*`,
  `rsync --exclude=/build*`). An unanchored `build*` also drops `packaging/build_signed_deb.sh` and `build_apt_repo.sh`, and a
  wrong `rsync --delete` exclude deletes the VM's build trees.
* `tests/e2e/run_package_e2e.sh` installs and purges the package: use a VM you can throw away.
* Sanitizer builds need more memory than Release; chaos runs use `MEMCAP_MB=512` for them.
* Power-loss chaos needs a hard power-off of the VM between its two runs (see `scenario_powerloss_crash` in
  `tests/chaos/run_chaos.sh`).
