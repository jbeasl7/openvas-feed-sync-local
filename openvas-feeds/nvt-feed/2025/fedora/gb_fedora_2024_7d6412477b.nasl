# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.7100641247798");
  script_cve_id("CVE-2024-56519", "CVE-2024-56521", "CVE-2024-56522", "CVE-2024-56527");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-7d6412477b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7d6412477b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-7d6412477b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334296");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334301");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334304");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334345");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-tcpdf' package(s) announced via the FEDORA-2024-7d6412477b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Version 6.8.0** (2024-12-23)

- Requires PHP 7.1+ and curl extension.
- Escape error message.
- Use strict time-constant function to compare TCPDF-tag hashes.
- Add K_CURLOPTS config array to set custom cURL options (NOTE: some defaults have changed).
- Add some addTTFfont fixes from tc-lib-pdf-font.");

  script_tag(name:"affected", value:"'php-tcpdf' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf", rpm:"php-tcpdf~6.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-lgc-sans-fonts", rpm:"php-tcpdf-dejavu-lgc-sans-fonts~6.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-lgc-sans-mono-fonts", rpm:"php-tcpdf-dejavu-lgc-sans-mono-fonts~6.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-lgc-serif-fonts", rpm:"php-tcpdf-dejavu-lgc-serif-fonts~6.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-sans-fonts", rpm:"php-tcpdf-dejavu-sans-fonts~6.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-sans-mono-fonts", rpm:"php-tcpdf-dejavu-sans-mono-fonts~6.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-serif-fonts", rpm:"php-tcpdf-dejavu-serif-fonts~6.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-mono-fonts", rpm:"php-tcpdf-gnu-free-mono-fonts~6.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-sans-fonts", rpm:"php-tcpdf-gnu-free-sans-fonts~6.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-serif-fonts", rpm:"php-tcpdf-gnu-free-serif-fonts~6.8.0~1.fc41", rls:"FC41"))) {
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
