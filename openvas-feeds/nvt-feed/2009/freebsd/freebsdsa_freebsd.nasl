# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66355");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2009-4358");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-09:17.freebsd.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"The freebsd-update(8) utility is used to fetch, install, and rollback
updates to the FreeBSD base system, and also to upgrade from one FreeBSD
release to another.

When downloading updates to FreeBSD via 'freebsd-update fetch' or
'freebsd-update upgrade', the freebsd-update(8) utility copies currently
installed files into its working directory (/var/db/freebsd-update by
default) both for the purpose of merging changes to configuration files
and in order to be able to roll back installed updates.

The default working directory used by freebsd-update(8) is normally
created during the installation of FreeBSD with permissions which allow
all local users to see its contents, and freebsd-update(8) does not take
any steps to restrict access to files stored in said directory.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-09:17.freebsd.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-09:17.freebsd.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"8.0", patchlevel:"1")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.2", patchlevel:"5")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"9")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.4", patchlevel:"8")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"14")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}