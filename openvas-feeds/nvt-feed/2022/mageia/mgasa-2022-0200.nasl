# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0200");
  script_cve_id("CVE-2022-29181");
  script_tag(name:"creation_date", value:"2022-05-23 04:32:41 +0000 (Mon, 23 May 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 02:12:45 +0000 (Tue, 07 Jun 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0200)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0200");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0200.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30451");
  script_xref(name:"URL", value:"https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-xh29-r2w5-wx8m");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4J4GGCK2IK6R7HJKHPGPCCZRBXEWHBVC/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-nokogiri' package(s) announced via the MGASA-2022-0200 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nokogiri did not type-check all inputs into the XML and HTML4 SAX parsers,
allowing specially crafted untrusted inputs to cause illegal memory access
errors (segfault) or reads from unrelated memory. Version 1.13.6 contains
a patch for this issue. As a workaround, ensure the untrusted input is a
'String' by calling '#to_s' or equivalent.");

  script_tag(name:"affected", value:"'ruby-nokogiri' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby-nokogiri", rpm:"ruby-nokogiri~1.11.7~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-nokogiri-doc", rpm:"ruby-nokogiri-doc~1.11.7~1.1.mga8", rls:"MAGEIA8"))) {
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
