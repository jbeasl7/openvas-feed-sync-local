# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3939.1");
  script_cve_id("CVE-2021-20266", "CVE-2021-20271", "CVE-2021-3421");
  script_tag(name:"creation_date", value:"2022-11-11 04:27:47 +0000 (Fri, 11 Nov 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-31 19:29:15 +0000 (Wed, 31 Mar 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3939-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3939-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223939-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996280");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-November/012871.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpm' package(s) announced via the SUSE-SU-2022:3939-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rpm fixes the following issues:

- Fixed PGP parsing bugs (bsc#1185299).
- Fixed various format handling bugs (bsc#996280).
- CVE-2021-3421: Fixed vulnerability where unsigned headers could be injected into the rpm database (bsc#1183543).
- CVE-2021-20271: Fixed vulnerability where a corrupted rpm could corrupt the rpm database (bsc#1183545).
- CVE-2021-20266: Fixed missing bounds check in hdrblobInit (bsc#1183632).

Bugfixes:

- Fixed deadlock when multiple rpm processes tried to acquire the database lock (bsc#1183659).");

  script_tag(name:"affected", value:"'rpm' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-rpm", rpm:"python3-rpm~4.11.2~16.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-32bit", rpm:"rpm-32bit~4.11.2~16.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.11.2~16.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-build", rpm:"rpm-build~4.11.2~16.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-python", rpm:"rpm-python~4.11.2~16.26.1", rls:"SLES12.0SP5"))) {
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
