# Dylib-Hijack-Scanner
JavaScript for Automation (JXA) version of Patrick Wardle's tool that searches applications for dylib hijacking opportunities

# Usage
```JavaScript
D00mfist: ~$ osascript -l JavaScript DyLibHijackScan.js
```
# To-Dos

* Automate weaponization based on scan results
* Add ability to scan a selected binary vs all open files (current implementation)
* Use underlying APIs rather than lsof, file, and otool (current implementation)
