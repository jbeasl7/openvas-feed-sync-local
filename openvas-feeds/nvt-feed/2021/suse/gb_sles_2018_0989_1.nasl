# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0989.1");
  script_cve_id("CVE-2017-13166", "CVE-2018-1000004", "CVE-2018-1068", "CVE-2018-7566");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-18 15:53:08 +0000 (Wed, 18 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0989-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180989-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085447");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-April/003905.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 14 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2018:0989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.90-92_45 fixes several issues.

The following security issues were fixed:

- CVE-2017-13166: Prevent elevation of privilege vulnerability in the v4l2 video driver (bsc#1085447).
- CVE-2018-1068: A flaw in the implementation of 32-bit syscall interface for bridging allowed a privileged user to arbitrarily write to a limited range of kernel memory (bsc#1085114).
- CVE-2018-7566: Prevent buffer overflow via an SNDRV_SEQ_IOCTL_SET_CLIENT_POOL ioctl write operation to /dev/snd/seq by a local user (bsc#1083488).
- CVE-2018-1000004: Prevent race condition in the sound system that could have lead to a deadlock and denial of service condition (bsc#1076017).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 14 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_90-92_45-default", rpm:"kgraft-patch-4_4_90-92_45-default~5~2.2", rls:"SLES12.0SP2"))) {
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
