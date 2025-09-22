# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0062");
  script_cve_id("CVE-2025-22376");
  script_tag(name:"creation_date", value:"2025-02-14 04:07:15 +0000 (Fri, 14 Feb 2025)");
  script_version("2025-02-14T08:35:38+0000");
  script_tag(name:"last_modification", value:"2025-02-14 08:35:38 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0062");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0062.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33923");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/GLAEBHWU2NBVEDHXVVKYY4Y2XLNJX2VX/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Crypt-URandom, perl-Module-Build, perl-Net-OAuth' package(s) announced via the MGASA-2025-0062 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Net::OAuth::Client in the Net::OAuth package before 0.29 for Perl,
the default nonce is a 32-bit integer generated from the built-in rand()
function, which is not cryptographically strong. (CVE-2025-22376)");

  script_tag(name:"affected", value:"'perl-Crypt-URandom, perl-Module-Build, perl-Net-OAuth' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Crypt-URandom", rpm:"perl-Crypt-URandom~0.370.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Build", rpm:"perl-Module-Build~0.423.400~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Net-OAuth", rpm:"perl-Net-OAuth~0.300.0~1.mga9", rls:"MAGEIA9"))) {
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
