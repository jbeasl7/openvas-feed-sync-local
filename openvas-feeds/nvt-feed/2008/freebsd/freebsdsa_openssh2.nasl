# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56352");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-0883");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-06:09.openssh.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"OpenSSH is an implementation of the SSH protocol suite, providing an
encrypted, authenticated transport for a variety of services,
including remote shell access.

Privilege separation is a mechanism used by OpenSSH to protect itself
against possible future vulnerabilities.  It works by splitting the
server process in two: the child process drops its privileges and
carries on the conversation with the client, while the parent retains
its privileges, monitors the child, and performs privileged operations
on behalf of the child when it is satisfied that everything is in
order. Privilege separation is enabled by default in FreeBSD.

OpenPAM is an implementation of the PAM framework, which allows the
use of loadable modules to implement user authentication and session
management in a manner defined by the administrator.  It is used by
OpenSSH and numerous other applications in FreeBSD to provide a
consistent and configurable authentication system.

Because OpenSSH and OpenPAM have conflicting designs (one is event-
driven while the other is callback-driven), it is necessary for
OpenSSH to fork a child process to handle calls to the PAM framework.
However, if the unprivileged child terminates while PAM authentication
is under way, the parent process incorrectly believes that the PAM
child also terminated.  The parent process then terminates, and the
PAM child is left behind.

Due to the way OpenSSH performs internal accounting, these orphaned
PAM children are counted as pending connections by the master OpenSSH
server process.  Once a certain number of orphans has accumulated, the
master decides that it is overloaded and stops accepting client
connections.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-06:09.openssh.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16892");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-06:09.openssh.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"5.4", patchlevel:"12")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"27")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}