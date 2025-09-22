# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0087");
  script_cve_id("CVE-2017-1000422");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-17 16:14:04 +0000 (Wed, 17 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0087)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0087");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0087.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22399");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3532-1/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4088");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf2.0' package(s) announced via the MGASA-2018-0087 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gnome gdk-pixbuf 2.36.8 and older is vulnerable to several integer
overflow in the gif_get_lzw function resulting in memory corruption and
potential code execution. (CVE-2017-1000422)");

  script_tag(name:"affected", value:"'gdk-pixbuf2.0' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf2.0", rpm:"gdk-pixbuf2.0~2.36.10~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf-gir2.0", rpm:"lib64gdk_pixbuf-gir2.0~2.36.10~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0-devel", rpm:"lib64gdk_pixbuf2.0-devel~2.36.10~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0_0", rpm:"lib64gdk_pixbuf2.0_0~2.36.10~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-gir2.0", rpm:"libgdk_pixbuf-gir2.0~2.36.10~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0-devel", rpm:"libgdk_pixbuf2.0-devel~2.36.10~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0_0", rpm:"libgdk_pixbuf2.0_0~2.36.10~1.2.mga6", rls:"MAGEIA6"))) {
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
