# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0056");
  script_cve_id("CVE-2012-2098");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0056)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0056");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0056.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=6331");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2012-June/081697.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-May/105060.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'plexus-archiver' package(s) announced via the MGASA-2014-0056 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Algorithmic complexity vulnerability in the sorting algorithms in bzip2
compressing stream (BZip2CompressorOutputStream) in Apache Commons Compress
before 1.4.1 allows remote attackers to cause a denial of service (CPU
consumption) via a file with many repeating inputs (CVE-2012-2098).

plexus-archiver used an embedded copy of the affected code from Apache
Commons Compress, and therefore was affected by this. It has been patched
to use the apache-commons-compress package, in which this issue has already
been fixed, for bzip2 compression and decompression.");

  script_tag(name:"affected", value:"'plexus-archiver' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"plexus-archiver", rpm:"plexus-archiver~2.3~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"plexus-archiver-javadoc", rpm:"plexus-archiver-javadoc~2.3~1.1.mga3", rls:"MAGEIA3"))) {
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
