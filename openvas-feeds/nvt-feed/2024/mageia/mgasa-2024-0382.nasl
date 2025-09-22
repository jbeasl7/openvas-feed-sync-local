# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0382");
  script_cve_id("CVE-2024-52530", "CVE-2024-52531", "CVE-2024-52532");
  script_tag(name:"creation_date", value:"2024-12-02 04:12:21 +0000 (Mon, 02 Dec 2024)");
  script_version("2024-12-03T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-12-03 05:05:44 +0000 (Tue, 03 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0382)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0382");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0382.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33765");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7126-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7127-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/11/09/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/11/12/8");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup, libsoup3' package(s) announced via the MGASA-2024-0382 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNOME libsoup before 3.6.0 allows HTTP request smuggling in some
configurations because '\0' characters at the end of header names are
ignored, i.e., a 'Transfer-Encoding\0: chunked' header is treated the
same as a 'Transfer-Encoding: chunked' header. (CVE-2024-52530)
GNOME libsoup before 3.6.1 allows a buffer overflow in applications that
perform conversion to UTF-8 in soup_header_parse_param_list_strict.
Input received over the network cannot trigger this. (CVE-2024-52531)
GNOME libsoup before 3.6.1 has an infinite loop, and memory consumption.
during the reading of certain patterns of WebSocket data from clients.
(CVE-2024-52532)");

  script_tag(name:"affected", value:"'libsoup, libsoup3' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64soup-devel", rpm:"lib64soup-devel~2.74.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup-gir2.4", rpm:"lib64soup-gir2.4~2.74.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup-gir3.0", rpm:"lib64soup-gir3.0~3.4.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup2.4_1", rpm:"lib64soup2.4_1~2.74.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup3-devel", rpm:"lib64soup3-devel~3.4.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64soup3.0_0", rpm:"lib64soup3.0_0~3.4.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.74.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~2.74.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-gir2.4", rpm:"libsoup-gir2.4~2.74.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-gir3.0", rpm:"libsoup-gir3.0~3.4.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-i18n", rpm:"libsoup-i18n~2.74.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup2.4_1", rpm:"libsoup2.4_1~2.74.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup3", rpm:"libsoup3~3.4.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup3-devel", rpm:"libsoup3-devel~3.4.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup3-i18n", rpm:"libsoup3-i18n~3.4.2~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup3.0_0", rpm:"libsoup3.0_0~3.4.2~1.1.mga9", rls:"MAGEIA9"))) {
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
