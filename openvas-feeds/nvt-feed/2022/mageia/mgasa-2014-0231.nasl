# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0231");
  script_cve_id("CVE-2014-1418", "CVE-2014-3730");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0231)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0231");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0231.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2212-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13384");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2014/may/14/security-releases-issued/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django, python-django14' package(s) announced via the MGASA-2014-0231 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-django and python-dgango14 packages fix security
vulnerabilities:

Stephen Stewart, Michael Nelson, Natalia Bidart and James Westby
discovered that Django improperly removed Vary and Cache-Control headers
from HTTP responses when replying to a request from an Internet Explorer
or Chrome Frame client. An attacker may use this to retrieve private data
or poison caches. This update removes workarounds for bugs in Internet
Explorer 6 and 7 (CVE-2014-1418).

Peter Kuma and Gavin Wahl discovered that Django did not correctly
validate some malformed URLs, which are accepted by some browsers. An
attacker may use this to cause unexpected redirects (CVE-2014-3730).");

  script_tag(name:"affected", value:"'python-django, python-django14' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.4.13~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.5.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django-doc", rpm:"python-django-doc~1.5.8~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django14", rpm:"python-django14~1.4.13~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~1.5.8~1.mga4", rls:"MAGEIA4"))) {
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
