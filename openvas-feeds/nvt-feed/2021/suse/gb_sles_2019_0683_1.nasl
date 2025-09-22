# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0683.1");
  script_cve_id("CVE-2019-6974", "CVE-2019-7221", "CVE-2019-9213");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:45 +0000 (Tue, 05 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0683-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0683-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190683-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128378");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-March/005215.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel (Live Patch 22 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2019:0683-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 4.4.121-92_80 fixes several issues.

The following security issues were fixed:

- CVE-2019-9213: Expand_downwards in mm/mmap.c lacked a check for the mmap minimum address, which made it easier for attackers to exploit kernel NULL pointer dereferences on non-SMAP platforms. This is related to a capability check for the wrong task (bsc#1128378).
- CVE-2019-7221: Fixed a user-after-free vulnerability in the KVM hypervisor related to the emulation of a preemption timer, allowing an guest user/process to crash the host kernel. (bsc#1124734).
- CVE-2019-6974: kvm_ioctl_create_device in virt/kvm/kvm_main.c mishandled reference counting because of a race condition, leading to a use-after-free (bsc#1124729).");

  script_tag(name:"affected", value:"'Linux Kernel (Live Patch 22 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_120-92_70-default", rpm:"kgraft-patch-4_4_120-92_70-default~11~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_73-default", rpm:"kgraft-patch-4_4_121-92_73-default~10~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_80-default", rpm:"kgraft-patch-4_4_121-92_80-default~10~2.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_85-default", rpm:"kgraft-patch-4_4_121-92_85-default~7~2.1", rls:"SLES12.0SP2"))) {
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
