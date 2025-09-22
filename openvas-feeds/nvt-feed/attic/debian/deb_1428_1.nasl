# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60007");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-31 16:11:48 +0100 (Thu, 31 Jan 2008)");
  script_cve_id("CVE-2007-3104", "CVE-2007-4997", "CVE-2007-5500");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Debian Security Advisory DSA 1428-1 (linux-2.6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201428-1");
  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2007-3104

Eric Sandeen provided a backport of Tejun Heo's fix for a local denial
of service vulnerability in sysfs. Under memory pressure, a dentry
structure maybe reclaimed resulting in a bad pointer dereference causing
an oops during a readdir.

CVE-2007-4997

Chris Evans discovered an issue with certain drivers that make use of the
Linux kernel's ieee80211 layer. A remote user could generate a malicious
802.11 frame that could result in a denial of service (crash). The ipw2100
driver is known to be affected by this issue, while the ipw2200 is
believed not to be.

CVE-2007-5500

Scott James Remnant diagnosed a coding error in the implementation of
ptrace which could be used by a local user to cause the kernel to enter
an infinite loop.

These problems have been fixed in the stable distribution in version
2.6.18.dfsg.1-13etch5.

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:

Debian 4.0 (etch)
fai-kernels                 1.17+etch.13etch5
user-mode-linux             2.6.18-1um-2etch.13etch5");

  script_tag(name:"solution", value:"We recommend that you upgrade your kernel package immediately and reboot");
  script_tag(name:"summary", value:"The remote host is missing an update to linux-2.6 announced via advisory DSA 1428-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1428)' (OID: 1.3.6.1.4.1.25623.1.0.60011).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
