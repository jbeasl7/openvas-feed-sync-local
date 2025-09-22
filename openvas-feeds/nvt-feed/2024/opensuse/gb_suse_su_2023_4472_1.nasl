# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833664");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-39323", "CVE-2023-39325", "CVE-2023-44487", "CVE-2023-45283", "CVE-2023-45284");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 18:04:15 +0000 (Thu, 04 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 07:48:01 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for go1.20 (SUSE-SU-2023:4472-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4472-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TPFWIF3RQHHIQAA32RXGODZFU3LW3BEX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.20'
  package(s) announced via the SUSE-SU-2023:4472-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.20-openssl fixes the following issues:

  Update to version 1.20.11.1 cut from the go1.20-openssl-fips branch at the
  revision tagged go1.20.11-1-openssl-fips.

  * Update to go1.20.11

  go1.20.11 (released 2023-11-07) includes security fixes to the path/filepath
  package, as well as bug fixes to the linker and the net/http package.

  * security: fix CVE-2023-45283 CVE-2023-45284 path/filepath: insecure parsing
      of Windows paths (bsc#1216943, bsc#1216944)

  * cmd/link: split text sections for arm 32-bit

  * net/http: http2 page fails on firefox/safari if pushing resources

  Update to version 1.20.10.1 cut from the go1.20-openssl-fips branch at the
  revision tagged go1.20.10-1-openssl-fips.

  * Update to go1.20.10

  go1.20.10 (released 2023-10-10) includes a security fix to the net/http package.

  * security: fix CVE-2023-39325 CVE-2023-44487 net/http: rapid stream resets
      can cause excessive work (bsc#1216109)

  go1.20.9 (released 2023-10-05) includes one security fixes to the cmd/go
  package, as well as bug fixes to the go command and the linker.

  * security: fix CVE-2023-39323 cmd/go: line directives allows arbitrary
      execution during build (bsc#1215985)

  * cmd/link: issues with Apple's new linker in Xcode 15 beta

  ##");

  script_tag(name:"affected", value:"'go1.20' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-doc", rpm:"go1.20-openssl-doc~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-debuginfo", rpm:"go1.20-openssl-debuginfo~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl", rpm:"go1.20-openssl~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-race", rpm:"go1.20-openssl-race~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-doc", rpm:"go1.20-openssl-doc~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-debuginfo", rpm:"go1.20-openssl-debuginfo~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl", rpm:"go1.20-openssl~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-race", rpm:"go1.20-openssl-race~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-doc", rpm:"go1.20-openssl-doc~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-debuginfo", rpm:"go1.20-openssl-debuginfo~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl", rpm:"go1.20-openssl~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-race", rpm:"go1.20-openssl-race~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-doc", rpm:"go1.20-openssl-doc~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-debuginfo", rpm:"go1.20-openssl-debuginfo~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl", rpm:"go1.20-openssl~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-race", rpm:"go1.20-openssl-race~1.20.11.1~150000.1.14.1", rls:"openSUSELeap15.5"))) {
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