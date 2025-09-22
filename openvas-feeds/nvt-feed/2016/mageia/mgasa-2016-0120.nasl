# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131278");
  script_cve_id("CVE-2014-1748", "CVE-2015-1071", "CVE-2015-1076", "CVE-2015-1081", "CVE-2015-1083", "CVE-2015-1120", "CVE-2015-1122", "CVE-2015-1127", "CVE-2015-1153", "CVE-2015-1155", "CVE-2015-3658", "CVE-2015-3659", "CVE-2015-3727", "CVE-2015-3731", "CVE-2015-3741", "CVE-2015-3743", "CVE-2015-3745", "CVE-2015-3747", "CVE-2015-3748", "CVE-2015-3749", "CVE-2015-3752", "CVE-2015-5788", "CVE-2015-5794", "CVE-2015-5801", "CVE-2015-5809", "CVE-2015-5822", "CVE-2015-5928");
  script_tag(name:"creation_date", value:"2016-03-31 05:05:03 +0000 (Thu, 31 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2016-0120)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0120");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0120.html");
  script_xref(name:"URL", value:"http://webkitgtk.org/security/WSA-2015-0002.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2016/03/14/webkitgtk2.4.10-released.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18018");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit' package(s) announced via the MGASA-2016-0120 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The webkit package has been updated to version 2.4.10, fixing several
security issues and other bugs.");

  script_tag(name:"affected", value:"'webkit' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir1.0", rpm:"lib64javascriptcore-gir1.0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir3.0", rpm:"lib64javascriptcore-gir3.0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk1.0_0", rpm:"lib64javascriptcoregtk1.0_0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk3.0_0", rpm:"lib64javascriptcoregtk3.0_0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit-gir1.0", rpm:"lib64webkit-gir1.0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit-gir3.0", rpm:"lib64webkit-gir3.0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk1.0-devel", rpm:"lib64webkitgtk1.0-devel~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk1.0_0", rpm:"lib64webkitgtk1.0_0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk3.0-devel", rpm:"lib64webkitgtk3.0-devel~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkitgtk3.0_0", rpm:"lib64webkitgtk3.0_0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir1.0", rpm:"libjavascriptcore-gir1.0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir3.0", rpm:"libjavascriptcore-gir3.0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk1.0_0", rpm:"libjavascriptcoregtk1.0_0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk3.0_0", rpm:"libjavascriptcoregtk3.0_0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit-gir1.0", rpm:"libwebkit-gir1.0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit-gir3.0", rpm:"libwebkit-gir3.0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk1.0-devel", rpm:"libwebkitgtk1.0-devel~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk1.0_0", rpm:"libwebkitgtk1.0_0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk3.0-devel", rpm:"libwebkitgtk3.0-devel~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk3.0_0", rpm:"libwebkitgtk3.0_0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit", rpm:"webkit~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-gtklauncher", rpm:"webkit-gtklauncher~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc", rpm:"webkit-jsc~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit1.0", rpm:"webkit1.0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit3", rpm:"webkit3~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit3-gtklauncher", rpm:"webkit3-gtklauncher~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit3-jsc", rpm:"webkit3-jsc~2.4.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit3.0", rpm:"webkit3.0~2.4.10~1.mga5", rls:"MAGEIA5"))) {
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
