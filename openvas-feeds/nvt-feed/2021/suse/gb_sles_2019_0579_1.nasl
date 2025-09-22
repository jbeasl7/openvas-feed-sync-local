# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0579.1");
  script_cve_id("CVE-2018-12178", "CVE-2018-12180", "CVE-2018-3630");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-01 15:23:54 +0000 (Mon, 01 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0579-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0579-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190579-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127822");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-March/005181.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ovmf' package(s) announced via the SUSE-SU-2019:0579-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ovmf fixes the following issues:

Security issues fixed:

- CVE-2018-12180: Fixed a buffer overflow in BlockIo service, which could lead
 to memory read/write overrun (bsc#1127820).
- CVE-2018-12178: Fixed an improper DNS check upon receiving a new DNS packet (bsc#1127821).
- CVE-2018-3630: Fixed a logic error in FV parsing which could allow a local attacker to
 bypass the chain of trust checks (bsc#1127822).");

  script_tag(name:"affected", value:"'ovmf' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ovmf", rpm:"ovmf~2017+git1492060560.b6d11d7c46~4.20.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovmf-tools", rpm:"ovmf-tools~2017+git1492060560.b6d11d7c46~4.20.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ovmf-x86_64", rpm:"qemu-ovmf-x86_64~2017+git1492060560.b6d11d7c46~4.20.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-uefi-aarch64", rpm:"qemu-uefi-aarch64~2017+git1492060560.b6d11d7c46~4.20.1", rls:"SLES12.0SP3"))) {
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
