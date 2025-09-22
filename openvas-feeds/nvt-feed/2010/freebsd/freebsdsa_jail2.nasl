# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67508");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-03 22:55:24 +0200 (Thu, 03 Jun 2010)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2010-2022");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-10:04.jail.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"The jail(2) system call allows a system administrator to lock a process
and all of its descendants inside an environment with a very limited
ability to affect the system outside that environment, even for
processes with superuser privileges.  It is an extension of, but
far more powerful than, the traditional UNIX chroot(2) system call.

By design, neither the chroot(2) nor the jail(2) system call modify
existing open file descriptors of the calling process, in order to
allow programmers to make fine grained access control and privilege
separation.

The jail(8) utility creates a new jail or modifies an existing jail,
optionally imprisoning the current process (and future descendants)
inside it.

The jail(8) utility does not change the current working directory while
imprisoning.  The current working directory can be accessed by its
descendants.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-10:04.jail.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-10:04.jail.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"8.0", patchlevel:"3")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}