# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.2632.1");
  script_cve_id("CVE-2023-49990", "CVE-2023-49991", "CVE-2023-49992", "CVE-2023-49993", "CVE-2023-49994");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-14 19:09:14 +0000 (Thu, 14 Dec 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2632-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2632-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242632-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218010");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-July/019042.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'espeak-ng' package(s) announced via the SUSE-SU-2024:2632-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for espeak-ng fixes the following issues:

- CVE-2023-49990: Fixed buffer overflow in SetUpPhonemeTable function at synthdata.c (bsc#1218010)
- CVE-2023-49991: Fixed stack-buffer-underflow exists in the function CountVowelPosition in synthdata.c (bsc#1218006)
- CVE-2023-49992: Fixed stack-buffer-overflow exists in the function RemoveEnding in dictionary.c (bsc#1218007)
- CVE-2023-49993: Fixed buffer overflow in ReadClause function at readclause.c (bsc#1218008)
- CVE-2023-49994: Fixed floating point exception in PeaksToHarmspect at wavegen.c (bsc#1218009)");

  script_tag(name:"affected", value:"'espeak-ng' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"espeak-ng", rpm:"espeak-ng~1.50~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"espeak-ng-compat", rpm:"espeak-ng-compat~1.50~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"espeak-ng-compat-devel", rpm:"espeak-ng-compat-devel~1.50~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"espeak-ng-devel", rpm:"espeak-ng-devel~1.50~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libespeak-ng1", rpm:"libespeak-ng1~1.50~150300.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"espeak-ng", rpm:"espeak-ng~1.50~150300.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"espeak-ng-compat", rpm:"espeak-ng-compat~1.50~150300.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"espeak-ng-compat-devel", rpm:"espeak-ng-compat-devel~1.50~150300.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"espeak-ng-devel", rpm:"espeak-ng-devel~1.50~150300.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libespeak-ng1", rpm:"libespeak-ng1~1.50~150300.3.3.1", rls:"openSUSELeap15.6"))) {
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
