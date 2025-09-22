# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1326.1");
  script_cve_id("CVE-2023-1907", "CVE-2024-4068", "CVE-2025-27152");
  script_tag(name:"creation_date", value:"2025-04-18 04:08:30 +0000 (Fri, 18 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-20 17:57:08 +0000 (Fri, 20 Jun 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1326-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1326-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251326-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239308");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/039030.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pgadmin4' package(s) announced via the SUSE-SU-2025:1326-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pgadmin4 fixes the following issues:

- CVE-2025-27152: Fixed SSRF and creadential leakage due to requests sent to absolute URL even when baseURL is set (bsc#1239308)
- CVE-2023-1907: Fixed an issue which could result in users being authenticated in another user's session if two users authenticate simultaneously via ldap (bsc#1234840)
- CVE-2024-4068: Fixed a possible memory exhaustion (bsc#1224295)");

  script_tag(name:"affected", value:"'pgadmin4' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4", rpm:"pgadmin4~4.30~150300.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-doc", rpm:"pgadmin4-doc~4.30~150300.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-web", rpm:"pgadmin4-web~4.30~150300.3.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4", rpm:"pgadmin4~4.30~150300.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-doc", rpm:"pgadmin4-doc~4.30~150300.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-web", rpm:"pgadmin4-web~4.30~150300.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4", rpm:"pgadmin4~4.30~150300.3.18.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-doc", rpm:"pgadmin4-doc~4.30~150300.3.18.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-web", rpm:"pgadmin4-web~4.30~150300.3.18.1", rls:"SLES15.0SP5"))) {
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
