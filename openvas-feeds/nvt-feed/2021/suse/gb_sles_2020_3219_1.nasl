# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3219.1");
  script_cve_id("CVE-2020-0429", "CVE-2020-0431", "CVE-2020-11668", "CVE-2020-14381", "CVE-2020-1749", "CVE-2020-25212");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 16:00:59 +0000 (Tue, 08 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3219-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3219-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203219-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176931");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007728.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 35 for SLE 12 SP3)' package(s) announced via the SUSE-SU-2020:3219-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.180-94_130 fixes several issues.

The following security issues were fixed:

- CVE-2020-0429: In l2tp_session_delete and related functions of l2tp_core.c, there is possible memory corruption due to a use after free. This could lead to local escalation of privilege with system execution privileges needed. User interaction is not needed for exploitation. (bsc#1176724)
- CVE-2020-14381: Fixed a use-after-free in the fast user mutex (futex) wait operation, which could have lead to memory corruption and possibly privilege escalation (bsc#1176011).
- CVE-2020-0431: In kbd_keycode of keyboard.c, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. (bsc#1176722)
- CVE-2020-25212: A TOCTOU mismatch in the NFS client code could be used by local attackers to corrupt memory or possibly have unspecified other impact because a size check is in fs/nfs/nfs4proc.c instead of fs/nfs/nfs4xdr.c (bsc#1176381).
- CVE-2020-11668: Fixed an out of bounds write to the heap in drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink camera USB driver) caused by mishandling invalid descriptors (bsc#1168952).
- CVE-2020-1749: A flaw was found in the implementation of some networking protocols in IPsec, such as VXLAN and GENEVE tunnels over IPv6. When an encrypted tunnel is created between two hosts, the kernel isn't correctly routing tunneled data over the encrypted link, rather sending the data unencrypted. This would have allowed anyone in between the two endpoints to read the traffic unencrypted. (bsc#1165629)");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 35 for SLE 12 SP3)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_141-default", rpm:"kgraft-patch-4_4_121-92_141-default~2~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_180-94_130-default", rpm:"kgraft-patch-4_4_180-94_130-default~2~2.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
