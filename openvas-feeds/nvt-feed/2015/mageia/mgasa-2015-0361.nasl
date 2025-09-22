# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130028");
  script_cve_id("CVE-2012-2150");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:42 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0361)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0361");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0361.html");
  script_xref(name:"URL", value:"http://oss.sgi.com/pipermail/xfs/2015-July/042726.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16455");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-August/163690.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xfsprogs' package(s) announced via the MGASA-2015-0361 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated xfsprogs packages fix security vulnerability:

xfs_metadump in xfsprogs before 3.2.4 does not properly obfuscate file data,
which allows remote attackers to obtain sensitive information by reading a
generated image (CVE-2012-2150).");

  script_tag(name:"affected", value:"'xfsprogs' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64xfs-devel", rpm:"lib64xfs-devel~3.2.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfs-static-devel", rpm:"lib64xfs-static-devel~3.2.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfs1", rpm:"lib64xfs1~3.2.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfs-devel", rpm:"libxfs-devel~3.2.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfs-static-devel", rpm:"libxfs-static-devel~3.2.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfs1", rpm:"libxfs1~3.2.4~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xfsprogs", rpm:"xfsprogs~3.2.4~1.mga5", rls:"MAGEIA5"))) {
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
