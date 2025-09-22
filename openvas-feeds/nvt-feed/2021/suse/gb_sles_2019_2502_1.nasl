# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2502.1");
  script_cve_id("CVE-2018-5740", "CVE-2018-5743", "CVE-2018-5745", "CVE-2019-6465", "CVE-2019-6471");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-01 15:47:02 +0000 (Fri, 01 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2502-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2502-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192502-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138687");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-October/005975.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2019:2502-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

Security issues fixed:

- CVE-2019-6465: Fixed an issue where controls for zone transfers may not be properly applied to Dynamically Loadable Zones (bsc#1126069).
- CVE-2019-6471: Fixed a reachable assert in dispatch.c. (bsc#1138687)
- CVE-2018-5745: Fixed a denial of service vulnerability if a trust anchor rolls over to an unsupported key algorithm when using managed-keys (bsc#1126068).
- CVE-2018-5743: Fixed a denial of service vulnerability which could be caused by to many simultaneous TCP connections (bsc#1133185).
- CVE-2018-5740: Fixed a denial of service vulnerability in the 'deny-answer-aliases' feature (bsc#1104129).

Non-security issues fixed:

- Don't rely on /etc/insserv.conf anymore for proper dependencies against
 nss-lookup.target in named.service and lwresd.service (bsc#1118367, bsc#1118368).
- Fix FIPS related regression (bsc#1128220).");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-160", rpm:"libbind9-160~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns169", rpm:"libdns169~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs160", rpm:"libirs160~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc166-32bit", rpm:"libisc166-32bit~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc166", rpm:"libisc166~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc160", rpm:"libisccc160~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg160", rpm:"libisccfg160~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblwres160", rpm:"liblwres160~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-bind", rpm:"python-bind~9.11.2~3.10.1", rls:"SLES12.0SP4"))) {
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
