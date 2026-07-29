# SG-Panel UI23 Repair4 — Updater Safety Fix 1

Local updater safety repair based on Manual Update Fix 1.

Fixed:
- the background progress spinner explicitly drops ERR/INT/TERM rollback traps;
- rollback is allowed only in the original installer shell (`MAIN_BASHPID` guard);
- rollback disables its traps before changing live files;
- project restore uses trailing-slash `rsync --delete` into an empty target instead of directory-to-directory `cp -a`, preventing `/opt/xpanel-mvp/xpanel-mvp` nesting;
- all UI and backend application files remain unchanged from Manual Update Fix 1.

No GitHub publication and no SG-Node update were performed.
