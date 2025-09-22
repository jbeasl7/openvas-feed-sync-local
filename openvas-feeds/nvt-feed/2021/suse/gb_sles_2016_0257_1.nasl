# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0257.1");
  script_cve_id("CVE-2009-0689", "CVE-2012-3543");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:08 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-22 18:38:35 +0000 (Fri, 22 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0257-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0257-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160257-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/739119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958097");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-January/001830.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mono-core' package(s) announced via the SUSE-SU-2016:0257-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mono-core was updated to fix the following vulnerabilities:

- CVE-2009-0689: Remote attackers could cause a denial of service and possibly arbitrary code execution through the string-to-double parser implementation (bsc#958097)
- CVE-2012-3543: Remote attackers could cause a denial of service through increased CPU consumption due to lack of protection against predictable hash collisions when processing form parameters (bsc#739119)");

  script_tag(name:"affected", value:"'mono-core' package(s) on SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"mono-core", rpm:"mono-core~2.6.7~0.16.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-data", rpm:"mono-data~2.6.7~0.16.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-data-postgresql", rpm:"mono-data-postgresql~2.6.7~0.16.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-data-sqlite", rpm:"mono-data-sqlite~2.6.7~0.16.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-locale-extras", rpm:"mono-locale-extras~2.6.7~0.16.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-nunit", rpm:"mono-nunit~2.6.7~0.16.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-web", rpm:"mono-web~2.6.7~0.16.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-winforms", rpm:"mono-winforms~2.6.7~0.16.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"mono-core", rpm:"mono-core~2.6.7~0.16.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-data", rpm:"mono-data~2.6.7~0.16.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-data-postgresql", rpm:"mono-data-postgresql~2.6.7~0.16.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-data-sqlite", rpm:"mono-data-sqlite~2.6.7~0.16.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-locale-extras", rpm:"mono-locale-extras~2.6.7~0.16.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-nunit", rpm:"mono-nunit~2.6.7~0.16.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-web", rpm:"mono-web~2.6.7~0.16.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mono-winforms", rpm:"mono-winforms~2.6.7~0.16.1", rls:"SLES11.0SP4"))) {
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
