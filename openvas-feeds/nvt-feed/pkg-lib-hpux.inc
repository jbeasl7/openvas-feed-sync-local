# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# This variable is defined at inclusion time. It's declared global and is set
# to True if ishpuxpkgvuln() is called for an OS version and a package name that
# match the target's configuration. It allows the callers to distinguish
# between non-installed packages and packages installed but not vulnerable.
__pkg_match = FALSE;

# Global keys to avoid that we're repeatedly asking redis for something we already know
global_var __hpux_ssh_release, __hpux_ssh_pkgrev, __hpux_ssh_pkgsupersedes;

# @brief returns the current release string of the target saved within the KB (ssh/login/release).
#
# @return a string containing the current release of the target or an empty string if no release
#         string exists in the KB.
#
# @todo Maybe move into a separate (new) include if other pkg-lib-*.inc includes needs this as well.
#
function hpux_get_ssh_release() {

  local_var rls;

  if( ! isnull( __hpux_ssh_release ) ) {
    rls = string( __hpux_ssh_release );
  } else {
    rls = string( get_kb_item( "ssh/login/release" ) );
    __hpux_ssh_release = rls;
  }
  return rls;
}

# @brief returns the output of "swlist -a revision -l fileset" of the target collected
#        by gather-package-list.nasl and saved within the KB (ssh/login/hp_pkgrev).
#
# @return a string containing the output of the command above or an empty string if
#         no output was returned / saved in the KB.
#
function hpux_get_ssh_pkgrev() {

  local_var pkgrev;

  if( ! isnull( __hpux_ssh_pkgrev ) ) {
    pkgrev = string( __hpux_ssh_pkgrev );
  } else {
    pkgrev = string( get_kb_item( "ssh/login/hp_pkgrev" ) );
    __hpux_ssh_pkgrev = pkgrev;
  }
  return pkgrev;
}

# @brief returns the output of "swlist -l patch -a supersedes" of the target collected
#        by gather-package-list.nasl and saved within the KB (ssh/login/hp_pkgsupersedes).
#
# @return a string containing the output of the command above or an empty string if
#         no output was returned / saved in the KB.
#
function hpux_get_ssh_pkgsupersedes() {

  local_var pkgsupersedes;

  if( ! isnull( __hpux_ssh_pkgsupersedes ) ) {
    pkgsupersedes = string( __hpux_ssh_pkgsupersedes );
  } else {
    pkgsupersedes = string( get_kb_item( "ssh/login/hp_pkgsupersedes" ) );
    __hpux_ssh_pkgsupersedes = pkgsupersedes;
  }
  return pkgsupersedes;
}

# @brief ishpuxpkgvuln is intended to provide a quick way to verify that a given
#        package, if it is installed, is vulnerable or not.
#
# @param pkg        TODO
# @param revision   TODO
# @param patch_list TODO
# @param rls        TODO
#
# @return NULL if a package is not installed or is installed but up to date, a string
#         containing a report about found package and the current installed version of
#         it if it is installed and vulnerable.
#
function ishpuxpkgvuln( pkg, revision, patch_list, rls ) {

  local_var pkg, revision, patch_list, rls;
  local_var kbrls, pkgs_rev, inst_rev, patches, _patch, rc, report;

  # Check that we have the data for this release.
  kbrls = hpux_get_ssh_release();
  if( kbrls != rls ) return NULL;

  pkgs_rev = hpux_get_ssh_pkgrev();
  # nb: The original code had a tab in the first pattern. Typo or was this intended?
  inst_rev = eregmatch( pattern:pkg + "(\t+| +)?([a-zA-Z0-9.]+) ", string:chomp( pkgs_rev ) );
  if( isnull( inst_rev ) ) return NULL;

  __pkg_match = TRUE;

  if( ! isnull( patch_list ) ) {
    patches = hpux_get_ssh_pkgsupersedes();
    foreach _patch( patch_list ) {
      if( _patch >!< patches ) {
        return "";
      }
    }
    return NULL;
  }

  rc = revcomp( a:inst_rev[2], b:revision );

  if( rc < 0 ) {
    report  = 'Vulnerable package: ' + pkg + '\n';
    report += 'Installed version:  ' + inst_rev[2] + '\n';
    report += 'Fixed version:      ' + revision + '\n\n';
    return report;
  }
  return NULL;
}
