# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64999");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-10-06 02:49:40 +0200 (Tue, 06 Oct 2009)");
  script_cve_id("CVE-2009-2903", "CVE-2009-3290", "CVE-2009-2847", "CVE-2009-2692", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-1895", "CVE-2009-1897", "CVE-2009-0065", "CVE-2008-5079", "CVE-2009-3001", "CVE-2009-3002");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 23:50:03 +0000 (Thu, 08 Feb 2024)");
  script_name("Fedora Core 10 FEDORA-2009-10165 (kernel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Update to kernel 2.6.27.35

ChangeLog:

  * Sat Sep 26 2009 Chuck Ebbert   2.6.27.35-170.2.94

  - Backport appletalk: Fix skb leak when ipddp interface is not loaded
(fixes CVE-2009-2903)

  * Sat Sep 26 2009 Chuck Ebbert   2.6.27.35-170.2.93

  - Backport KVM: x86: Disallow hypercalls for guest callers in rings > 0
(fixes CVE-2009-3290)

  * Thu Sep 24 2009 Chuck Ebbert   2.6.27.35-170.2.92

  - Linux 2.6.27.35

  - Drop merged patches:
linux-2.6-nfsd-report-short-writes-fix.patch
linux-2.6-nfsd-report-short-writes.patch

  * Tue Sep 15 2009 Chuck Ebbert   2.6.27.34-170.2.91

  - Linux 2.6.27.34

  - Drop merged patch: linux-2.6-slub-fix-destroy-by-rcu.patch

  * Wed Sep  9 2009 Chuck Ebbert   2.6.27.32-170.2.90

  - 2.6.27.32 final

  - Drop linux-2.6-ocfs2-handle-len-0.patch, added after .32-rc1

  * Mon Sep  7 2009 Chuck Ebbert   2.6.27.32-170.2.89.rc1

  - Backport fix for b43 on ppc64 to 2.6.27 (#514787)

  * Sun Sep  6 2009 Chuck Ebbert   2.6.27.32-170.2.88.rc1

  - Add patches requested for the next stable release:
linux-2.6-slub-fix-destroy-by-rcu.patch (fixes bug in 2.6.27.29)
linux-2.6-ocfs2-handle-len-0.patch (fixes bug in 2.6.27.32-rc1)

  * Fri Sep  4 2009 Chuck Ebbert   2.6.27.32-170.2.87.rc1

  - Copy fix for NFS short write reporting from F-10 2.6.29 kernel (#493500)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kernel' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10165");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel
announced via advisory FEDORA-2009-10165.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=515392");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=524124");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=522331");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=519305");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
