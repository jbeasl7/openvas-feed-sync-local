# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131282");
  script_cve_id("CVE-2015-1068", "CVE-2015-1069", "CVE-2015-1070", "CVE-2015-1071", "CVE-2015-1072", "CVE-2015-1073", "CVE-2015-1075", "CVE-2015-1076", "CVE-2015-1077", "CVE-2015-1081", "CVE-2015-1082", "CVE-2015-1119", "CVE-2015-1120", "CVE-2015-1121", "CVE-2015-1122", "CVE-2015-1124", "CVE-2015-1126", "CVE-2015-1127", "CVE-2015-1152", "CVE-2015-1153", "CVE-2015-1154", "CVE-2015-1155", "CVE-2015-1156", "CVE-2015-3658", "CVE-2015-3659", "CVE-2015-3660", "CVE-2015-3727", "CVE-2015-3730", "CVE-2015-3731", "CVE-2015-3732", "CVE-2015-3733", "CVE-2015-3734", "CVE-2015-3735", "CVE-2015-3736", "CVE-2015-3737", "CVE-2015-3738", "CVE-2015-3739", "CVE-2015-3740", "CVE-2015-3741", "CVE-2015-3742", "CVE-2015-3743", "CVE-2015-3744", "CVE-2015-3745", "CVE-2015-3746", "CVE-2015-3747", "CVE-2015-3748", "CVE-2015-3749", "CVE-2015-3750", "CVE-2015-3751", "CVE-2015-3752", "CVE-2015-3753", "CVE-2015-3754", "CVE-2015-3755", "CVE-2015-5788", "CVE-2015-5793", "CVE-2015-5794", "CVE-2015-5795", "CVE-2015-5797", "CVE-2015-5799", "CVE-2015-5800", "CVE-2015-5801", "CVE-2015-5803", "CVE-2015-5804", "CVE-2015-5805", "CVE-2015-5806", "CVE-2015-5807", "CVE-2015-5809", "CVE-2015-5810", "CVE-2015-5811", "CVE-2015-5812", "CVE-2015-5813", "CVE-2015-5814", "CVE-2015-5815", "CVE-2015-5816", "CVE-2015-5817", "CVE-2015-5818", "CVE-2015-5819", "CVE-2015-5822", "CVE-2015-5823", "CVE-2015-5825", "CVE-2015-5827", "CVE-2015-5828", "CVE-2015-5928", "CVE-2015-5929", "CVE-2015-5930", "CVE-2015-5931", "CVE-2015-7002", "CVE-2015-7012", "CVE-2015-7013", "CVE-2015-7014", "CVE-2015-7048", "CVE-2015-7095", "CVE-2015-7096", "CVE-2015-7097", "CVE-2015-7098", "CVE-2015-7099", "CVE-2015-7100", "CVE-2015-7102", "CVE-2015-7103", "CVE-2015-7104", "CVE-2016-1723", "CVE-2016-1724", "CVE-2016-1725", "CVE-2016-1726", "CVE-2016-1727", "CVE-2016-1728");
  script_tag(name:"creation_date", value:"2016-03-31 05:05:06 +0000 (Thu, 31 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-16 15:50:11 +0000 (Tue, 16 Feb 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0116)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0116");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0116.html");
  script_xref(name:"URL", value:"http://webkitgtk.org/security/WSA-2015-0002.html");
  script_xref(name:"URL", value:"http://webkitgtk.org/security/WSA-2016-0001.html");
  script_xref(name:"URL", value:"http://webkitgtk.org/security/WSA-2016-0002.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2015/04/14/webkitgtk2.8.1-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2015/05/12/webkitgtk2.8.2-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2015/07/08/webkitgtk2.8.4-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2015/08/06/webkitgtk2.8.5-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2015/09/21/webkitgtk2.10.0-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2015/10/14/webkitgtk2.10.1-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2015/10/15/webkitgtk2.10.2-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2015/10/26/webkitgtk2.10.3-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2015/11/11/webkitgtk2.10.4-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2016/01/20/webkitgtk2.10.5-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2016/01/27/webkitgtk2.10.6-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2016/01/29/webkitgtk2.10.7-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2016/03/11/webkitgtk2.10.8-released.html");
  script_xref(name:"URL", value:"http://www.webkitgtk.org/2016/03/17/webkitgtk2.10.9-released.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17662");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2' package(s) announced via the MGASA-2016-0116 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The webkit2 package has been updated to version 2.10.9, fixing several
security issues and other bugs.");

  script_tag(name:"affected", value:"'webkit2' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir4.0", rpm:"lib64javascriptcore-gir4.0~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk4.0_18", rpm:"lib64javascriptcoregtk4.0_18~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2-devel", rpm:"lib64webkit2-devel~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk-gir4.0", rpm:"lib64webkit2gtk-gir4.0~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.0_37", rpm:"lib64webkit2gtk4.0_37~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir4.0", rpm:"libjavascriptcore-gir4.0~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk4.0_18", rpm:"libjavascriptcoregtk4.0_18~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2-devel", rpm:"libwebkit2-devel~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-gir4.0", rpm:"libwebkit2gtk-gir4.0~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.0_37", rpm:"libwebkit2gtk4.0_37~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2", rpm:"webkit2~2.10.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2-jsc", rpm:"webkit2-jsc~2.10.9~1.mga5", rls:"MAGEIA5"))) {
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
