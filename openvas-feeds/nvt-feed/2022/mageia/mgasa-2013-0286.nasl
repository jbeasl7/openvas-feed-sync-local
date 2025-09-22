# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0286");
  script_cve_id("CVE-2013-4331");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0286)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0286");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0286.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2013/09/11/4");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11071");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11219");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lightdm' package(s) announced via the MGASA-2013-0286 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"lightdm before 1.4.3, 1.6.2 and 1.7.14 created .Xauthority files with
world-readable permissions (CVE-2013-4331).

Additionally, an issue where a user logged into a graphical desktop
environment through lightdm would lose privileges to local devices (such as
the sound card) when using the 'su' command has been fixed.");

  script_tag(name:"affected", value:"'lightdm' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64lightdm-gir1", rpm:"lib64lightdm-gir1~1.4.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lightdm-gobject-devel", rpm:"lib64lightdm-gobject-devel~1.4.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lightdm-gobject1_0", rpm:"lib64lightdm-gobject1_0~1.4.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lightdm-qt-devel", rpm:"lib64lightdm-qt-devel~1.4.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64lightdm-qt2_0", rpm:"lib64lightdm-qt2_0~1.4.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblightdm-gir1", rpm:"liblightdm-gir1~1.4.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblightdm-gobject-devel", rpm:"liblightdm-gobject-devel~1.4.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblightdm-gobject1_0", rpm:"liblightdm-gobject1_0~1.4.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblightdm-qt-devel", rpm:"liblightdm-qt-devel~1.4.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblightdm-qt2_0", rpm:"liblightdm-qt2_0~1.4.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lightdm", rpm:"lightdm~1.4.3~1.mga3", rls:"MAGEIA3"))) {
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
