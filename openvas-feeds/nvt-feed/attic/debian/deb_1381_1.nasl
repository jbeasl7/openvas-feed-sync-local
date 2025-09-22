# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58641");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2006-5755", "CVE-2007-4133", "CVE-2007-4573", "CVE-2007-5093");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1381-1 (linux-2.6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201381-1");
  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in the Linux kernel
that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2006-5755

The NT bit maybe leaked into the next task which can local attackers
to cause a Denial of Service (crash) on systems which run the 'amd64'
flavour kernel. The stable distribution ('etch') was not believed to
be vulnerable to this issue at the time of release, however Bastian
Blank discovered that this issue still applied to the 'xen-amd64' and
'xen-vserver-amd64' flavours, and is resolved by this DSA.

CVE-2007-4133

Hugh Dickins discovered a potential local DoS (panic) in hugetlbfs.
A misconversion of hugetlb_vmtruncate_list to prio_tree may allow
local users to trigger a BUG_ON() call in exit_mmap.

CVE-2007-4573

Wojciech Purczynski discovered a vulnerability that can be exploited
by a local user to obtain superuser privileges on x86_64 systems.
This resulted from improper clearing of the high bits of registers
during ia32 system call emulation. This vulnerability is relevant
to the Debian amd64 port as well as users of the i386 port who run
the amd64 linux-image flavour.

DSA-1378 resolved this problem for the 'amd64' flavour kernels, but
Tim Wickberg and Ralf Hemmenstaedt reported an outstanding issue with
the 'xen-amd64' and 'xen-vserver-amd64' issues that is resolved by
this DSA.

CVE-2007-5093

Alex Smith discovered an issue with the pwc driver for certain webcam
devices. If the device is removed while a userspace application has it
open, the driver will wait for userspace to close the device, resulting
in a blocked USB subsystem. This issue is of low security impact as
it requires the attacker to either have physical access to the system
or to convince a user with local access to remove the device on their
behalf.

These problems have been fixed in the stable distribution in version
2.6.18.dfsg.1-13etch4.

At the time of this DSA, only the build for the amd64 architecture is
available. Due to the severity of the amd64-specific issues, we are
releasing an incomplete update. This advisory will be updated once
other architecture builds become available.");

  script_tag(name:"solution", value:"We recommend that you upgrade your kernel package immediately and reboot");
  script_tag(name:"summary", value:"The remote host is missing an update to linux-2.6 announced via advisory DSA 1381-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1381)' (OID: 1.3.6.1.4.1.25623.1.0.58667).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
