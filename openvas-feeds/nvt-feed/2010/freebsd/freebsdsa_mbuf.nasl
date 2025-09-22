# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67716");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-22 17:43:43 +0200 (Thu, 22 Jul 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2693");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-10:07.mbuf.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"An mbuf is a basic unit of memory management in the FreeBSD kernel
inter-process communication and networking subsystem.  Network packets
and socket buffers are dependent on mbufs for their storage.

Data can be embedded directly in mbufs, or mbufs can instead reference
external buffers.  The sendfile(2) system call uses external mbuf storage
to directly map the contents of a file into a chain of mbufs for
transmission purposes.  The mbuf object supports a read-only flag that
must be honored to prevent modification or writes to buffer data in
cases like these.

The read-only flag is not correctly copied when a mbuf buffer reference
is duplicated.  When the sendfile(2) system call is used to transmit
data over the loopback interface, this can result in the backing pages
for the transmitted file being modified, causing data corruption.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-10:07.mbuf.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-10:07.mbuf.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"8.0", patchlevel:"4")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.3", patchlevel:"2")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"13")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}