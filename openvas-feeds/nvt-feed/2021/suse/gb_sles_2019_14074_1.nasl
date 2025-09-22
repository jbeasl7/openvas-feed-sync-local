# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14074.1");
  script_cve_id("CVE-2018-5740", "CVE-2018-5743", "CVE-2018-5745", "CVE-2019-6465");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-01 15:47:02 +0000 (Fri, 01 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14074-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14074-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914074-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133185");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-June/005537.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2019:14074-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

Security issues fixed:

- CVE-2018-5740: Fixed a denial of service vulnerability in the 'deny-answer-aliases' feature (bsc#1104129).
- CVE-2018-5743: Limiting simultaneous TCP clients is ineffective. (bsc#1133185)
- CVE-2018-5745: An assertion failure can occur if a trust anchor rolls over to an unsupported key algorithm when using managed-keys. (bsc#1126068)
- CVE-2019-6465: Fixed an issue where controls for zone transfers may not be properly applied to Dynamically Loadable Zones (bsc#1126069).");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.9.6P1~0.51.15.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.9.6P1~0.51.15.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.9.6P1~0.51.15.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.9.6P1~0.51.15.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.9.6P1~0.51.15.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.9.6P1~0.51.15.4", rls:"SLES11.0SP4"))) {
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
