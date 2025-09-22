# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131181");
  script_cve_id("CVE-2015-4499", "CVE-2015-8508", "CVE-2015-8509");
  script_tag(name:"creation_date", value:"2016-01-14 05:28:54 +0000 (Thu, 14 Jan 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-05 18:41:45 +0000 (Tue, 05 Jan 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0006)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0006");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0006.html");
  script_xref(name:"URL", value:"http://lwn.net/Vulnerabilities/671083/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16776");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-January/175113.html");
  script_xref(name:"URL", value:"https://www.bugzilla.org/releases/4.4.10/release-notes.html");
  script_xref(name:"URL", value:"https://www.bugzilla.org/releases/4.4.11/release-notes.html");
  script_xref(name:"URL", value:"https://www.bugzilla.org/security/4.2.14/");
  script_xref(name:"URL", value:"https://www.bugzilla.org/security/4.2.15/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bugzilla' package(s) announced via the MGASA-2016-0006 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Login names (usually an email address) longer than 127 characters are
silently truncated in MySQL which could cause the domain name of the email
address to be corrupted. An attacker could use this vulnerability to
create an account with an email address different from the one originally
requested. The login name could then be automatically added to groups
based on the group's regular expression setting (CVE-2015-4499).

During the generation of a dependency graph, the code for the HTML image
map is generated locally if a local dot installation is used. With escaped
HTML characters in a bug summary, it is possible to inject unfiltered HTML
code in the map file which the CreateImagemap function generates. This
could be used for a cross-site scripting attack (CVE-2015-8508).

If an external HTML page contains a 'script' tag with its src
attribute pointing to a buglist in CSV format, some web browsers
incorrectly try to parse the CSV file as valid JavaScript code. As the
buglist is generated based on the privileges of the user logged into
Bugzilla, the external page could collect confidential data contained in
the CSV file (CVE-2015-8509).

The bugzilla package has been updated to version 4.4.11, fixing these
issues and a few other bugs.");

  script_tag(name:"affected", value:"'bugzilla' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"bugzilla", rpm:"bugzilla~4.4.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bugzilla-contrib", rpm:"bugzilla-contrib~4.4.11~1.mga5", rls:"MAGEIA5"))) {
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
