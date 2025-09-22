# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130057");
  script_cve_id("CVE-2015-5963", "CVE-2015-5964");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:08 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0327)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0327");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0327.html");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2720-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16607");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2015/aug/18/security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django, python-django14' package(s) announced via the MGASA-2015-0327 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lin Hua Cheng discovered that Django incorrectly handled the session store.
A remote attacker could use this issue to cause the session store to fill
up, resulting in a denial of service.");

  script_tag(name:"affected", value:"'python-django, python-django14' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"python-django14", rpm:"python-django14~1.4.22~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.8.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django-bash-completion", rpm:"python-django-bash-completion~1.8.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django-doc", rpm:"python-django-doc~1.8.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~1.8.4~1.mga5", rls:"MAGEIA5"))) {
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
