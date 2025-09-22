# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131120");
  script_cve_id("CVE-2015-8001", "CVE-2015-8002", "CVE-2015-8003", "CVE-2015-8004", "CVE-2015-8005");
  script_tag(name:"creation_date", value:"2015-11-08 11:02:15 +0000 (Sun, 08 Nov 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0421)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0421");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0421.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/10/29/14");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16990");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-October/000181.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2015-0421 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated mediawiki packages fix security vulnerabilities:

In MediaWiki before 1.23.11, the API failed to correctly stop adding new
chunks to the upload when the reported size was exceeded, allowing a
malicious user to upload add an infinite number of chunks for a single file
upload (CVE-2015-8001).

In MediaWiki before 1.23.11, a malicious user could upload chunks of 1 byte
for very large files, potentially creating a very large number of files on
the server's filesystem (CVE-2015-8002).

In MediaWiki before 1.23.11, it is not possible to throttle file uploads,
or in other words, rate limit them (CVE-2015-8003).

In MediaWiki before 1.23.11, a missing authorization check when removing
suppression from a revision allowed users with the 'viewsuppressed' user
right but not the appropriate 'suppressrevision' user right to unsuppress
revisions (CVE-2015-8004).

In MediaWiki before 1.23.11, thumbnails of PNG files generated with
ImageMagick contained the local file path in the image (CVE-2015-8005).");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.23.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.23.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.23.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.23.11~1.mga5", rls:"MAGEIA5"))) {
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
