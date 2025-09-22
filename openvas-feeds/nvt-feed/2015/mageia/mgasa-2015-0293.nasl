# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130085");
  script_cve_id("CVE-2015-5143", "CVE-2015-5144", "CVE-2015-5145");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:31 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0293)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0293");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0293.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16334");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3305");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2015/jul/08/security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django, python-django14' package(s) announced via the MGASA-2015-0293 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eric Peterson and Lin Hua Cheng discovered that a new empty record used to be
created in the session storage every time a session was accessed and an
unknown session key was provided in the request cookie. This could allow
remote attackers to saturate the session store or cause other users' session
records to be evicted (CVE-2015-5143).

Sjoerd Job Postmus discovered that some built-in validators did not properly
reject newlines in input values. This could allow remote attackers to inject
headers in emails and HTTP responses (CVE-2015-5144).

django.core.validators.URLValidator included a regular expression that was
extremely slow to evaluate against certain inputs. This regular expression has
been simplified and optimized (CVE-2015-5145).

The Mageia 4 python-django14 and Mageia 5 python-django packages have been
updated to versions 1.4.21 and 1.8.3 respectively to fix these issues. Note
that the CVE-2015-5145 issue only affected python-django.

Note: the python-django package in Mageia 4, based on Django 1.5.9, is no
longer supported. Users of this package are advised to migrate to Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-django14", rpm:"python-django14~1.4.21~1.mga4", rls:"MAGEIA4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.8.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django-bash-completion", rpm:"python-django-bash-completion~1.8.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django-doc", rpm:"python-django-doc~1.8.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~1.8.3~1.mga5", rls:"MAGEIA5"))) {
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
