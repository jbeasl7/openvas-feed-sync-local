# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.9800678990897");
  script_cve_id("CVE-2024-22641");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-b00678c08a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-b00678c08a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-b00678c08a");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-tcpdf' package(s) announced via the FEDORA-2024-b00678c08a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Version 6.7.7** (2024-10-26)

- Update regular expression to avoid ReDoS (**CVE-2024-22641**)
- [PHP 8.4] Fix: Curl CURLOPT_BINARYTRANSFER deprecated #675
- SVG detection fix for inline data images #646
- Fix count svg #647
- Since the version 6.7.4, the '0' is considered like empty string and not displayed
- Fixed handling of transparency in PDF/A mode in addExtGState method
- Encrypt /DA string when document is encrypted
- Improve quality of generated seed, avoid potential security pitfall
- Try to use random_bytes() first if it's available
- Do not include the server parameters in the generated seed, as they might contain sensitive data
- Fix bug on _getannotsrefs when there are empty signature appearances but not other annot on a page
- Fix SVG coordinate parser that caused drawing artifacts
- Remove usage of xml_set_object() function");

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

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf", rpm:"php-tcpdf~6.7.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-lgc-sans-fonts", rpm:"php-tcpdf-dejavu-lgc-sans-fonts~6.7.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-lgc-sans-mono-fonts", rpm:"php-tcpdf-dejavu-lgc-sans-mono-fonts~6.7.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-lgc-serif-fonts", rpm:"php-tcpdf-dejavu-lgc-serif-fonts~6.7.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-sans-fonts", rpm:"php-tcpdf-dejavu-sans-fonts~6.7.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-sans-mono-fonts", rpm:"php-tcpdf-dejavu-sans-mono-fonts~6.7.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-dejavu-serif-fonts", rpm:"php-tcpdf-dejavu-serif-fonts~6.7.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-mono-fonts", rpm:"php-tcpdf-gnu-free-mono-fonts~6.7.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-sans-fonts", rpm:"php-tcpdf-gnu-free-sans-fonts~6.7.7~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-tcpdf-gnu-free-serif-fonts", rpm:"php-tcpdf-gnu-free-serif-fonts~6.7.7~1.fc41", rls:"FC41"))) {
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
