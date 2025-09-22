# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0336");
  script_cve_id("CVE-2017-17456", "CVE-2017-17457", "CVE-2018-13139");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-24 17:22:57 +0000 (Fri, 24 Aug 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0336)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0336");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0336.html");
  script_xref(name:"URL", value:"http://lists.suse.com/pipermail/sle-security-updates/2018-July/004311.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23382");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsndfile' package(s) announced via the MGASA-2018-0336 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libsndfile package fixes security vulnerabilities:

The function d2alaw_array() in alaw.c of libsndfile 1.0.29pre1 may lead
to a remote DoS attack (CVE-2017-17456).

The function d2ulaw_array() in ulaw.c of libsndfile 1.0.29pre1 may lead
to a remote DoS attack (CVE-2017-17457).

A stack-based buffer overflow in psf_memset in common.c in libsndfile
1.0.28 allows remote attackers to cause a denial of service (application
crash) or possibly have unspecified other impact via a crafted audio file
(CVE-2018-13139).");

  script_tag(name:"affected", value:"'libsndfile' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64sndfile-devel", rpm:"lib64sndfile-devel~1.0.28~3.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sndfile-static-devel", rpm:"lib64sndfile-static-devel~1.0.28~3.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sndfile1", rpm:"lib64sndfile1~1.0.28~3.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile", rpm:"libsndfile~1.0.28~3.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile-devel", rpm:"libsndfile-devel~1.0.28~3.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile-progs", rpm:"libsndfile-progs~1.0.28~3.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile-static-devel", rpm:"libsndfile-static-devel~1.0.28~3.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsndfile1", rpm:"libsndfile1~1.0.28~3.3.mga6", rls:"MAGEIA6"))) {
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
