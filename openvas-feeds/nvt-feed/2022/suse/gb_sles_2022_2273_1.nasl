# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2273.1");
  script_cve_id("CVE-2021-3839", "CVE-2022-0669");
  script_tag(name:"creation_date", value:"2022-07-06 04:40:49 +0000 (Wed, 06 Jul 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-26 19:24:20 +0000 (Fri, 26 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2273-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2273-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222273-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198964");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-July/011406.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpdk' package(s) announced via the SUSE-SU-2022:2273-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dpdk fixes the following issues:

- CVE-2021-3839: Fixed a memory corruption issue during vhost-user communication
 (bsc#1198963).
- CVE-2022-0669: Fixed a denial of service that could be triggered by a vhost-user
 master (bsc#1198964).

- rebuild with new secure boot key due to grub2 boothole 3 issues (bsc#1198581)");

  script_tag(name:"affected", value:"'dpdk' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"dpdk", rpm:"dpdk~19.11.4~150200.3.17.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel", rpm:"dpdk-devel~19.11.4~150200.3.17.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default", rpm:"dpdk-kmp-default~19.11.4_k5.3.18_150200.24.115~150200.3.17.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx", rpm:"dpdk-thunderx~19.11.4~150200.3.17.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-devel", rpm:"dpdk-thunderx-devel~19.11.4~150200.3.17.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-default", rpm:"dpdk-thunderx-kmp-default~19.11.4_k5.3.18_150200.24.115~150200.3.17.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools", rpm:"dpdk-tools~19.11.4~150200.3.17.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-20_0", rpm:"libdpdk-20_0~19.11.4~150200.3.17.1", rls:"SLES15.0SP2"))) {
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
