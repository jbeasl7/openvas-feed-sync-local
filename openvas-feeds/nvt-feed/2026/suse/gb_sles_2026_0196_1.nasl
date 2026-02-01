# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0196.1");
  script_cve_id("CVE-2023-45231", "CVE-2023-45232", "CVE-2023-45233", "CVE-2023-45234", "CVE-2023-45235");
  script_tag(name:"creation_date", value:"2026-01-23 04:21:16 +0000 (Fri, 23 Jan 2026)");
  script_version("2026-01-23T05:49:25+0000");
  script_tag(name:"last_modification", value:"2026-01-23 05:49:25 +0000 (Fri, 23 Jan 2026)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-23 15:58:27 +0000 (Tue, 23 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0196-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0196-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260196-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218885");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023832.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ovmf' package(s) announced via the SUSE-SU-2026:0196-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ovmf fixes the following issues:

- CVE-2023-45231: Fixed out of bounds read when handling a ND Redirect message with truncated options (bsc#1218881).
- CVE-2023-45232: Fixed infinite loop when parsing unknown options in the Destination Options header (bsc#1218882).
- CVE-2023-45233: Fixed infinite loop when parsing a PadN option in the Destination Options header (bsc#1218883).
- CVE-2023-45234: Fixed buffer overflow when processing DNS Servers option in a DHCPv6 Advertise message (bsc#1218884).
- CVE-2023-45235: Fixed buffer overflow when handling Server ID option from a DHCPv6 proxy Advertise message (bsc#1218885).");

  script_tag(name:"affected", value:"'ovmf' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"ovmf", rpm:"ovmf~2017+git1510945757.b2662641d5~3.55.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovmf-tools", rpm:"ovmf-tools~2017+git1510945757.b2662641d5~3.55.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ovmf-x86_64", rpm:"qemu-ovmf-x86_64~2017+git1510945757.b2662641d5~3.55.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-uefi-aarch64", rpm:"qemu-uefi-aarch64~2017+git1510945757.b2662641d5~3.55.1", rls:"SLES12.0SP5"))) {
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
