# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0462");
  script_tag(name:"creation_date", value:"2022-12-14 04:11:58 +0000 (Wed, 14 Dec 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0462)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0462");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0462.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31232");
  script_xref(name:"URL", value:"https://phabricator.services.mozilla.com/D163527");
  script_xref(name:"URL", value:"https://utcc.utoronto.ca/~cks/space/blog/linux/CARootStoreTrustProblem");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rootcerts' package(s) announced via the MGASA-2022-0462 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Set CKA_NSS_SERVER_DISTRUST_AFTER and CKA_NSS_EMAIL_DISTRUST_AFTER for 3
TrustCor Root Certificates. r=KathleenWilson");

  script_tag(name:"affected", value:"'rootcerts' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"rootcerts", rpm:"rootcerts~20221130.00~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rootcerts-java", rpm:"rootcerts-java~20221130.00~1.mga8", rls:"MAGEIA8"))) {
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
