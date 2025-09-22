# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833221");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-20251", "CVE-2022-37966", "CVE-2022-38023");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 22:15:16 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:41:20 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for samba (SUSE-SU-2023:0222-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0222-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/V3YTRBE2CLOHDFXSGJQCTU4DTNHNRTBU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the SUSE-SU-2023:0222-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

  - CVE-2021-20251: Fixed an issue where the bad password count would not be
       properly incremented, which could allow attackers to brute force a
       user's password (bsc#1206546).

  - CVE-2022-38023: Disabled weak ciphers by default in the Netlogon Secure
       channel (bsc#1206504).

  - CVE-2022-37966: Fixed an issue where a weak cipher would be selected to
       encrypt session keys, which could lead to privilege escalation
       (bsc#1205385).");

  script_tag(name:"affected", value:"'samba' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python-devel", rpm:"libsamba-policy-python-devel~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0", rpm:"libsamba-policy0~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-debuginfo", rpm:"libsamba-policy0-debuginfo~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python", rpm:"samba-libs-python~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python-debuginfo", rpm:"samba-libs-python-debuginfo~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python-debuginfo", rpm:"samba-python-debuginfo~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-32bit", rpm:"libsamba-policy0-32bit~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-32bit-debuginfo", rpm:"libsamba-policy0-32bit-debuginfo~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python-32bit", rpm:"samba-libs-python-32bit~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python-32bit-debuginfo", rpm:"samba-libs-python-32bit-debuginfo~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python-devel", rpm:"libsamba-policy-python-devel~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0", rpm:"libsamba-policy0~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-debuginfo", rpm:"libsamba-policy0-debuginfo~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python", rpm:"samba-libs-python~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python-debuginfo", rpm:"samba-libs-python-debuginfo~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python-debuginfo", rpm:"samba-python-debuginfo~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-32bit", rpm:"libsamba-policy0-32bit~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-32bit-debuginfo", rpm:"libsamba-policy0-32bit-debuginfo~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python-32bit", rpm:"samba-libs-python-32bit~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python-32bit-debuginfo", rpm:"samba-libs-python-32bit-debuginfo~4.9.5+git.552.fec1a5e57a~150100.3.73.1", rls:"openSUSELeap15.4"))) {
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