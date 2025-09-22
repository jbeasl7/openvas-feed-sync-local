# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0159");
  script_cve_id("CVE-2018-20004", "CVE-2018-20005", "CVE-2018-20592", "CVE-2018-20593");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-01 19:10:02 +0000 (Fri, 01 Feb 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0159)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0159");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0159.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24583");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/N53IJHDYR5HVQLKH4J6B27OEQLGKSGY5/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mxml' package(s) announced via the MGASA-2019-0159 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated mxml packages fix security vulnerabilities:

An issue has been found in Mini-XML (aka mxml) 2.12. It is a stack-based
buffer overflow in mxml_write_node in mxml-file.c via vectors involving
a double-precision floating point number and the '<order type='real'>'
substring, as demonstrated by testmxml (CVE-2018-20004).

An issue has been found in Mini-XML (aka mxml) 2.12. It is a
use-after-free in mxmlWalkNext in mxml-search.c, as demonstrated by
mxmldoc (CVE-2018-20005).

In Mini-XML (aka mxml) v2.12, there is a use-after-free in the mxmlAdd
function of the mxml-node.c file. Remote attackers could leverage this
vulnerability to cause a denial-of-service via a crafted xml file, as
demonstrated by mxmldoc (CVE-2018-20592).

In Mini-XML (aka mxml) v2.12, there is stack-based buffer overflow in
the scan_file function in mxmldoc.c (CVE-2018-20593).");

  script_tag(name:"affected", value:"'mxml' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64mxml-devel", rpm:"lib64mxml-devel~3.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mxml1", rpm:"lib64mxml1~3.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmxml-devel", rpm:"libmxml-devel~3.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmxml1", rpm:"libmxml1~3.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mxml", rpm:"mxml~3.0~1.mga6", rls:"MAGEIA6"))) {
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
