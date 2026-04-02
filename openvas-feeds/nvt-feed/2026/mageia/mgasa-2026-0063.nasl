# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0063");
  script_cve_id("CVE-2006-10002", "CVE-2006-10003");
  script_tag(name:"creation_date", value:"2026-03-25 04:42:47 +0000 (Wed, 25 Mar 2026)");
  script_version("2026-03-25T05:58:02+0000");
  script_tag(name:"last_modification", value:"2026-03-25 05:58:02 +0000 (Wed, 25 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-19 18:16:12 +0000 (Thu, 19 Mar 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0063)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0063");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0063.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35238");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/03/19/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/03/19/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-XML-Parser' package(s) announced via the MGASA-2026-0063 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XML::Parser versions through 2.47 for Perl could overflow the
pre-allocated buffer size causing a heap corruption (double free or
corruption) and crashes. (CVE-2006-10002)
XML::Parser versions through 2.47 for Perl has an off-by-one heap buffer
overflow in st_serial_stack. (CVE-2006-10003)");

  script_tag(name:"affected", value:"'perl-XML-Parser' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-XML-Parser", rpm:"perl-XML-Parser~2.460.0~6.1.mga9", rls:"MAGEIA9"))) {
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
