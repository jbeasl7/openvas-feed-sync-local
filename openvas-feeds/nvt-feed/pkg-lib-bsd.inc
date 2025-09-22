# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# This variable is defined at inclusion time. It's declared global and is set
# to True if portver() is called for an OS version and a package name that
# match the target's configuration. It allows the callers to distinguish
# between non-installed packages and packages installed but not vulnerable.
__pkg_match = FALSE;

# portver is a quick and easy way for us to determine if a particular package
# exists on a freebsd system., and if so, to return the version number of
# that package.
function portver(pkg) {

  local_var pkg;
  local_var pkgs, narrowed, list, _package, pat, matches;

  pkgs = get_kb_item("ssh/login/freebsdpkg");
  if(!pkgs)
    return(NULL);

  narrowed = egrep(pattern:"^" + pkg + "-[0-9]", string:pkgs);
  if(!narrowed)
    return(NULL);

  # Package was installed
  __pkg_match = TRUE;

  list = split(narrowed, sep:'\n', keep:FALSE);
  foreach _package(list) {
    pat = string("^", pkg, "-([^ -]+) (.*)$");
    matches = eregmatch(pattern:pat, string:_package);
    if(!isnull(matches)) {
      return(matches[1]);
    }
  }
  return(NULL);
}

# Function to verify if a given patch level is outdated, and if so, to
# report that fact. Relies on the kb to contain bsdrel and patchlevel.
function patchlevelcmp(rel, patchlevel) {

  local_var rel, patchlevel;
  local_var kbrel, kbpatchlevel;

  kbrel = get_kb_item("ssh/login/freebsdrel");
  if(kbrel != rel)
    return(0);

  kbpatchlevel = int(get_kb_item("ssh/login/freebsdpatchlevel"));
  if(kbpatchlevel < int(patchlevel)) {
    return(-1);
  } else if(kbpatchlevel > int(patchlevel)) {
    return(1);
  } else {
    return(0);
  }
}
