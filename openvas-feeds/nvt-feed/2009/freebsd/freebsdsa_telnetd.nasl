# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63418");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2009-0641");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-18 23:13:28 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-09:05.telnetd.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"The FreeBSD telnet daemon, telnetd(8), implements the server side of the
TELNET virtual terminal protocol.  It has been disabled by default in
FreeBSD since August 2001, and due to the lack of cryptographic security
in the TELNET protocol, it is strongly recommended that the SSH protocol
be used instead.  The FreeBSD telnet daemon can be enabled via the
/etc/inetd.conf configuration file and the inetd(8) daemon.

The TELNET protocol allows a connecting client to specify environment
variables which should be set in any created login session. This is used,
for example, to specify terminal settings.

In order to prevent environment variable based attacks, telnetd(8) scrubs
its environment. However, recent changes in FreeBSD's environment-handling
code rendered telnetd's scrubbing inoperative, thereby allowing potentially
harmful environment variables to be set.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-09:05.telnetd.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-09:05.telnetd.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"7.1", patchlevel:"10")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.0", patchlevel:"3")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}