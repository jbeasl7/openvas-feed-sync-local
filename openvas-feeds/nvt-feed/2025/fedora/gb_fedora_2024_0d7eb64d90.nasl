# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.01007101986410090");
  script_cve_id("CVE-2024-20505", "CVE-2024-20506");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-12 17:28:47 +0000 (Thu, 12 Sep 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-0d7eb64d90)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-0d7eb64d90");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-0d7eb64d90");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300593");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the FEDORA-2024-0d7eb64d90 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 1.0.7

* CVE-2024-20506: Changed the logging module to disable following symlinks on Linux and Unix systems so as to prevent an attacker with existing access to the 'clamd' or 'freshclam' services from using a symlink to corrupt system files.
* CVE-2024-20505: Fixed a possible out-of-bounds read bug in the PDF file parser that could cause a denial-of-service (DoS) condition.");

  script_tag(name:"affected", value:"'clamav' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-data", rpm:"clamav-data~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-doc", rpm:"clamav-doc~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-filesystem", rpm:"clamav-filesystem~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-freshclam", rpm:"clamav-freshclam~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-freshclam-debuginfo", rpm:"clamav-freshclam-debuginfo~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-lib", rpm:"clamav-lib~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-lib-debuginfo", rpm:"clamav-lib-debuginfo~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter-debuginfo", rpm:"clamav-milter-debuginfo~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamd", rpm:"clamd~1.0.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamd-debuginfo", rpm:"clamd-debuginfo~1.0.7~1.fc41", rls:"FC41"))) {
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
