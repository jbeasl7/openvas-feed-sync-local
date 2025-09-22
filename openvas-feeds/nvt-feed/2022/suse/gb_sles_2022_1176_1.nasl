# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1176.1");
  script_cve_id("CVE-2022-1097", "CVE-2022-1196", "CVE-2022-1197", "CVE-2022-24713", "CVE-2022-28281", "CVE-2022-28282", "CVE-2022-28285", "CVE-2022-28286", "CVE-2022-28289");
  script_tag(name:"creation_date", value:"2022-04-13 14:37:21 +0000 (Wed, 13 Apr 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-30 20:42:45 +0000 (Fri, 30 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1176-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1176-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221176-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2022:1176-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Updated to version 91.8 (bsc#1197903):
 - CVE-2022-1097: Fixed a memory corruption issue with NSSToken objects.
 - CVE-2022-28281: Fixed a memory corruption issue due to unexpected
 WebAuthN Extensions.
 - CVE-2022-1197: Fixed an issue where OpenPGP revocation information was
 ignored.
 - CVE-2022-1196: Fixed a memory corruption issue after VR process
 destruction.
 - CVE-2022-28282: Fixed a memory corruption issue in document
 translation.
 - CVE-2022-28285: Fixed a memory corruption issue in JIT code generation.
 - CVE-2022-28286: Fixed an iframe layout issue that could have been
 exploited to stage spoofing attacks.
 - CVE-2022-24713: Fixed a potential denial of service via complex
 regular expressions.
 - CVE-2022-28289: Fixed multiple memory corruption issues.

Non-security fixes:

Changed Google accounts using password authentication to use OAuth2.

Fixed an issue where OpenPGP ECC keys created by Thunderbird could not
 be imported into GnuPG.

Fixed an issue where exporting multiple public PGP keys from Thunderbird
 was not possible.

Fixed an issue where replying to a newsgroup message erroneously
 displayed a 'No-reply' popup warning.

Fixed an issue with opening older address books.

Fixed an issue where LDAP directories would be lost when switching to
 'Offline' mode.

Fixed an issue when importing webcals.");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~91.8.0~150200.8.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~91.8.0~150200.8.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~91.8.0~150200.8.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~91.8.0~150200.8.65.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~91.8.0~150200.8.65.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~91.8.0~150200.8.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~91.8.0~150200.8.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~91.8.0~150200.8.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~91.8.0~150200.8.65.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~91.8.0~150200.8.65.1", rls:"SLES15.0SP4"))) {
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
