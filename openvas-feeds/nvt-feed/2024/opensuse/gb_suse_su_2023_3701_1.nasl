# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833013");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-39318", "CVE-2023-39319", "CVE-2023-39320", "CVE-2023-39321", "CVE-2023-39322");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-12 14:39:48 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:59:59 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for go1.21 (SUSE-SU-2023:3701-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3701-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QZPRU5LDPSUFIDLEQJ3EWITFVLBAIYMN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.21'
  package(s) announced via the SUSE-SU-2023:3701-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.21 fixes the following issues:

  Update to go1.21.1 (bsc#1212475).

  * CVE-2023-39318: Fixed improper handling of HTML-like comments within script
      contexts in html/template (bsc#1215084).

  * CVE-2023-39319: Fixed improper handling of special tags within script
      contexts in html/template (bsc#1215085).

  * CVE-2023-39320: Fixed arbitrary execution in go.mod toolchain directive
      (bsc#1215086).

  * CVE-2023-39321, CVE-2023-39322: Fixed a panic when processing post-handshake
      message on QUIC connections in crypto/tls (bsc#1215087).

  The following non-security bug was fixed:

  * Add missing directory pprof html asset directory to package (bsc#1215090).

  ##");

  script_tag(name:"affected", value:"'go1.21' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.21-doc", rpm:"go1.21-doc~1.21.1~150000.1.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-race", rpm:"go1.21-race~1.21.1~150000.1.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21", rpm:"go1.21~1.21.1~150000.1.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-doc", rpm:"go1.21-doc~1.21.1~150000.1.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-race", rpm:"go1.21-race~1.21.1~150000.1.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21", rpm:"go1.21~1.21.1~150000.1.6.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.21-doc", rpm:"go1.21-doc~1.21.1~150000.1.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-race", rpm:"go1.21-race~1.21.1~150000.1.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21", rpm:"go1.21~1.21.1~150000.1.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-doc", rpm:"go1.21-doc~1.21.1~150000.1.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-race", rpm:"go1.21-race~1.21.1~150000.1.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21", rpm:"go1.21~1.21.1~150000.1.6.1", rls:"openSUSELeap15.5"))) {
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