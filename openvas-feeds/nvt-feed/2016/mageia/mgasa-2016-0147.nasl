# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131302");
  script_cve_id("CVE-2016-3995");
  script_tag(name:"creation_date", value:"2016-05-09 11:18:04 +0000 (Mon, 09 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-03 16:13:10 +0000 (Fri, 03 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0147)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0147");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0147.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18184");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-April/182297.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcryptopp' package(s) announced via the MGASA-2016-0147 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libcryptopp packages fix security vulnerability:

In libcryptopp, for both Rijndael::Enc::ProcessAndXorBlock and
Rijndael::Dec::ProcessAndXorBlock there is some code to avoid timing attacks,
however it is removed by the compiler due to optimizations, making the binary
vulnerable to timing attacks (CVE-2016-3995).

This update also corrects some bugs with the package.");

  script_tag(name:"affected", value:"'libcryptopp' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64cryptopp-devel", rpm:"lib64cryptopp-devel~5.6.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cryptopp6", rpm:"lib64cryptopp6~5.6.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptopp", rpm:"libcryptopp~5.6.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptopp-devel", rpm:"libcryptopp-devel~5.6.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptopp-progs", rpm:"libcryptopp-progs~5.6.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptopp6", rpm:"libcryptopp6~5.6.3~1.1.mga5", rls:"MAGEIA5"))) {
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
