# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130066");
  script_cve_id("CVE-2015-4491");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:17 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0313)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0313");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0313.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/08/13/2");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16367");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-88/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf2.0' package(s) announced via the MGASA-2015-0313 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security researcher Gustavo Grieco reported a heap overflow in gdk-pixbuf.
This issue is triggered by the scaling of a malformed bitmap format image
and results in a potentially exploitable crash (CVE-2015-4491).");

  script_tag(name:"affected", value:"'gdk-pixbuf2.0' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf2.0", rpm:"gdk-pixbuf2.0~2.31.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf-gir2.0", rpm:"lib64gdk_pixbuf-gir2.0~2.31.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0-devel", rpm:"lib64gdk_pixbuf2.0-devel~2.31.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0_0", rpm:"lib64gdk_pixbuf2.0_0~2.31.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-gir2.0", rpm:"libgdk_pixbuf-gir2.0~2.31.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0-devel", rpm:"libgdk_pixbuf2.0-devel~2.31.2~2.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0_0", rpm:"libgdk_pixbuf2.0_0~2.31.2~2.1.mga5", rls:"MAGEIA5"))) {
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
