# SPDX-FileCopyrightText: 2007 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# This variable is defined at inclusion time. It's declared global and is set
# to TRUE if isslkpkgvuln() is called for an OS version and a package name that
# match the target's configuration. It allows the callers to distinguish
# between non-installed packages and packages installed but not vulnerable.
__pkg_match = FALSE;

# Global keys to avoid that we're repeatedly asking redis for something we already know
global_var __slk_ssh_release, __slk_ssh_pkgs;

# @brief returns the current release string of the target saved within the KB (ssh/login/release).
#
# @return a string containing the current release of the target or an empty string if no release
#         string exists in the KB.
#
# @todo Maybe move into a separate (new) include if other pkg-lib-*.inc includes needs this as well.
#
function slk_get_ssh_release() {

  local_var rls;

  if( ! isnull( __slk_ssh_release ) ) {
    rls = string( __slk_ssh_release );
  } else {
    rls = string( get_kb_item( "ssh/login/release" ) );
    __slk_ssh_release = rls;
  }
  return rls;
}

# @brief returns the current installed packages of the target collected by gather-package-list.nasl
#        and saved within the KB (ssh/login/slackpack).
#
# @return a string containing the current installed packages of the target or an empty string if no
#         package list exists in the KB.
#
function slk_get_ssh_pkgs() {

  local_var pkgs;

  if( ! isnull( __slk_ssh_pkgs ) ) {
    pkgs = string( __slk_ssh_pkgs );
  } else {
    pkgs = string( get_kb_item( "ssh/login/slackpack" ) );
    __slk_ssh_pkgs = pkgs;
  }
  return pkgs;
}

# @brief Checks the knowledgebase to see if a older version of the passed package is installed
#        (listed in /var/log/packages) on the Slackware system. The listing is held in the KB
#        "ssh/login/slackpack"
#
# @param pkg the packagename (e.g. sendmail-cf) to check.
# @param rpm the version of the package (e.g. e.g. 8.12.11) which contains a fix for
#            the related vulnerability.
# @param rls a release string in a form of e.g. "SLK10.0" which needs to exactly
#            match the collected release (set by gather-package-list.nasl) so
#            hat the vulnerability is checked.
#
# @return NULL if a package is not installed or is installed but up to date, a string
#         containing a report about the found package and the current installed version of
#         it if it is installed and vulnerable.
#
function isslkpkgvuln( pkg, ver, rls ) {

  local_var pkg, ver, rls;
  local_var kbrls, pkgs, narrowed, list, fixed_pkg, _inst_pkg, rc, report, ver_split, arch;

  # Package names have always the following structure:
  # packagename-version-architecture-buildnumber.tgz
  # according to the following presentation:
  # http://www.slackware.com/~mozes/docs/slackware_pkg_presentation.pdf
  # At this point "ver" doesn't include the package name so the index 1 is the one we need
  ver_split = split( ver, sep:"-", keep:FALSE );
  # nb: "-" is prepended before and after the arch to make the later check a little bit more strict.
  arch = "-" + ver_split[1] + "-";

  kbrls = slk_get_ssh_release();
  if( rls != kbrls )
    return NULL;

  pkgs = slk_get_ssh_pkgs();
  if( ! pkgs )
    return NULL;

  narrowed = egrep( pattern:"^" + pkg + "-[0-9]", string:pkgs );
  if( ! narrowed )
    return NULL;

  list = split( narrowed, keep:FALSE );

  __pkg_match = TRUE;
  fixed_pkg = pkg + "-" + ver;

  foreach _inst_pkg( list ) {
    # revcomp() is not designed to compare different architectures (e.g. i586 vs. x86_64) in the
    # package, so we need to skip packages with different architectures to prevent false positives.
    if( arch >!< _inst_pkg )
      continue;

    rc = revcomp( a:_inst_pkg, b:fixed_pkg );
    if( rc < 0 ) {
      report  = 'Vulnerable package: ' + pkg + '\n';
      report += 'Installed version:  ' + _inst_pkg + '\n';
      report += 'Fixed version:      ' + fixed_pkg + '\n\n';
      return report;
    }
  }
  return NULL;
}
