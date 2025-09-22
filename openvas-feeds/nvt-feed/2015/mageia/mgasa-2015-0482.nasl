# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131164");
  script_cve_id("CVE-2015-0860");
  script_tag(name:"creation_date", value:"2015-12-28 08:39:27 +0000 (Mon, 28 Dec 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0482)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0482");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0482.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17239");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3407");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpkg' package(s) announced via the MGASA-2015-0482 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated dpkg packages fix security vulnerability:

Hanno Boeck discovered a stack-based buffer overflow in the dpkg-deb component
of dpkg. This flaw could potentially lead to arbitrary code execution if a user
or an automated system were tricked into processing a specially crafted Debian
binary package (.deb) in the old style Debian binary package format
(CVE-2015-0860).");

  script_tag(name:"affected", value:"'dpkg' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"dpkg", rpm:"dpkg~1.17.26~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Dpkg", rpm:"perl-Dpkg~1.17.26~1.mga5", rls:"MAGEIA5"))) {
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
