# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0376");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0376)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0376");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0376.html");
  script_xref(name:"URL", value:"http://bugs.python.org/issue17997#msg194950");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11283");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11785");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1023742");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-November/122682.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bzr, python3, python-pip, python-requests, python-setuptools, python-tornado, python-urllib3, python-virtualenv' package(s) announced via the MGASA-2013-0376 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Changed behavior of ssl.match_hostname() to follow RFC 6125

Also python-virtualenv has had inc_dir settings altered to avoid
'#include nested too deeply' error (mga#11283)");

  script_tag(name:"affected", value:"'bzr, python3, python-pip, python-requests, python-setuptools, python-tornado, python-urllib3, python-virtualenv' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"bzr", rpm:"bzr~2.5.1~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3-devel", rpm:"lib64python3-devel~3.3.0~4.5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.3", rpm:"lib64python3.3~3.3.0~4.5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3-devel", rpm:"libpython3-devel~3.3.0~4.5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.3", rpm:"libpython3.3~3.3.0~4.5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pip", rpm:"python-pip~1.3.1~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pkg-resources", rpm:"python-pkg-resources~0.9.8~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-requests", rpm:"python-requests~0.13.5~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-setuptools", rpm:"python-setuptools~0.9.8~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado", rpm:"python-tornado~2.3~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tornado-doc", rpm:"python-tornado-doc~2.3~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-urllib3", rpm:"python-urllib3~1.7.1~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualenv", rpm:"python-virtualenv~1.10.1~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.3.0~4.5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.3.0~4.5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pip", rpm:"python3-pip~1.3.1~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pkg-resources", rpm:"python3-pkg-resources~0.9.8~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-setuptools", rpm:"python3-setuptools~0.9.8~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3", rpm:"tkinter3~3.3.0~4.5.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3-apps", rpm:"tkinter3-apps~3.3.0~4.5.mga3", rls:"MAGEIA3"))) {
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
