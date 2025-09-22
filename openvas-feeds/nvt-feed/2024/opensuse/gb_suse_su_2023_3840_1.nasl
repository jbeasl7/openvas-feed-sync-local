# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833754");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-29409", "CVE-2023-39318", "CVE-2023-39319");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-12 15:09:14 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:54:46 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for go1.20 (SUSE-SU-2023:3840-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3840-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HZFLZVOKJOZYESYPHHQNBIUYQ4XP2IDS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.20'
  package(s) announced via the SUSE-SU-2023:3840-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.20-openssl fixes the following issues:

  Update to version 1.20.8 (bsc#1206346).

  * CVE-2023-29409: Fixed unrestricted RSA keys in certificates (bsc#1213880).

  * CVE-2023-39319: Fixed improper handling of special tags within script
      contexts in html/template (bsc#1215085).

  * CVE-2023-39318: Fixed improper handling of HTML-like comments within script
      contexts (bsc#1215084).

  The following non-security bug was fixed:

  * Add missing directory pprof html asset directory to package (bsc#1215090).

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

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl", rpm:"go1.20-openssl~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-race", rpm:"go1.20-openssl-race~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-debuginfo", rpm:"go1.20-openssl-debuginfo~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-doc", rpm:"go1.20-openssl-doc~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl", rpm:"go1.20-openssl~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-race", rpm:"go1.20-openssl-race~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-debuginfo", rpm:"go1.20-openssl-debuginfo~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-doc", rpm:"go1.20-openssl-doc~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl", rpm:"go1.20-openssl~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-race", rpm:"go1.20-openssl-race~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-debuginfo", rpm:"go1.20-openssl-debuginfo~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-doc", rpm:"go1.20-openssl-doc~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl", rpm:"go1.20-openssl~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-race", rpm:"go1.20-openssl-race~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-debuginfo", rpm:"go1.20-openssl-debuginfo~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-openssl-doc", rpm:"go1.20-openssl-doc~1.20.8.1~150000.1.11.1", rls:"openSUSELeap15.5"))) {
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