# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0121.1");
  script_cve_id("CVE-2024-12085", "CVE-2024-12086", "CVE-2024-12087", "CVE-2024-12088");
  script_tag(name:"creation_date", value:"2025-01-15 23:25:54 +0000 (Wed, 15 Jan 2025)");
  script_version("2025-06-19T05:40:14+0000");
  script_tag(name:"last_modification", value:"2025-06-19 05:40:14 +0000 (Thu, 19 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-18 16:29:29 +0000 (Wed, 18 Jun 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0121-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0121-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250121-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsync' package(s) announced via the SUSE-SU-2025:0121-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rsync fixes the following issues:

CVE-2024-12085: leak of uninitialized stack data on the server leading to possible ASLR bypass. (bsc#1234101)
CVE-2024-12086: leak of a client machine's file contents through the processing of checksum data. (bsc#1234102)
CVE-2024-12087: arbitrary file overwrite possible on clients when symlink syncing is enabled. (bsc#1234103)
CVE-2024-12088: bypass of the --safe-links flag may allow the placement of unsafe symlinks in a client. (bsc#1234104)");

  script_tag(name:"affected", value:"'rsync' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.2.3~150000.4.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsync-debuginfo", rpm:"rsync-debuginfo~3.2.3~150000.4.28.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsync-debugsource", rpm:"rsync-debugsource~3.2.3~150000.4.28.1", rls:"SLES15.0SP3"))) {
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
