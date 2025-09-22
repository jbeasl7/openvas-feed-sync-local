# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71530");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-0217");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: FreeBSD");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: FreeBSD

CVE-2012-0217
The x86-64 kernel system-call functionality in Xen 4.1.2 and earlier,
as used in Citrix XenServer 6.0.2 and earlier and other products,
Oracle Solaris 11 and earlier, illumos before r13724, Joyent SmartOS
before 20120614T184600Z, FreeBSD before 9.0-RELEASE-p3, NetBSD 6.0
Beta and earlier, and Microsoft Windows Server 2008 R2 and R2 SP1 and
Windows 7 Gold and SP1, when running on an Intel processor,
incorrectly uses the sysret path in cases where a certain address is
not a canonical address, which allows local users to gain privileges
via a crafted application.  NOTE: this description clearly does not
belong in CVE, because a single entry cannot be about independent
codebases. However, there was some value in preserving the original
mapping of the multi-codebase coordinated-disclosure effort to a
single identifier.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);