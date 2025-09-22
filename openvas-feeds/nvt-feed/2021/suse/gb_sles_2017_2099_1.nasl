# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2099.1");
  script_cve_id("CVE-2017-2636", "CVE-2017-7533", "CVE-2017-7645", "CVE-2017-9242");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-21 16:01:39 +0000 (Fri, 21 Apr 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2099-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2099-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172099-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050751");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-August/003117.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel Live Patch 16 for SLE 12' package(s) announced via the SUSE-SU-2017:2099-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 3.12.60-52_57 fixes several issues.

The following security bugs were fixed:

- CVE-2017-7533: A bug in inotify code allowed local users to escalate privilege (bsc#1050751).
- CVE-2017-7645: The NFSv2/NFSv3 server in the nfsd subsystem in the Linux kernel allowed remote attackers to cause a denial of service (system crash) via a long RPC reply, related to net/sunrpc/svc.c, fs/nfsd/nfs3xdr.c, and fs/nfsd/nfsxdr.c (bsc#1046191).
- CVE-2017-2636: Race condition in drivers/tty/n_hdlc.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (double free) by setting the HDLC line discipline (bsc#1027575).
- CVE-2017-9242: The __ip6_append_data function in net/ipv6/ip6_output.c in the Linux kernel is too late in checking whether an overwrite of an skb data structure may occur, which allowed local users to cause a denial of service (system crash) via crafted system calls (bsc#1042892).");

  script_tag(name:"affected", value:"'Linux Kernel Live Patch 16 for SLE 12' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_60-52_57-default", rpm:"kgraft-patch-3_12_60-52_57-default~8~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_60-52_57-xen", rpm:"kgraft-patch-3_12_60-52_57-xen~8~2.1", rls:"SLES12.0"))) {
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
