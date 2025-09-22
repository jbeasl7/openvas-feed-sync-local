# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0557");
  script_cve_id("CVE-2014-3577", "CVE-2014-3584");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0557)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0557");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0557.html");
  script_xref(name:"URL", value:"http://cxf.apache.org/security-advisories.data/CVE-2014-3577.txt.asc");
  script_xref(name:"URL", value:"http://cxf.apache.org/security-advisories.data/CVE-2014-3584.txt.asc");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14363");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1129074");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1157330");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cxf' package(s) announced via the MGASA-2014-0557 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated cxf packages fix security vulnerabilities:

An Apache CXF JAX-RS service can process SAML tokens received in the
authorization header of a request via the SamlHeaderInHandler. However it is
possible to cause an infinite loop in the parsing of this header by passing
certain bad values for the header, leading to a Denial of Service attack on
the service (CVE-2014-3584).

Apache CXF is vulnerable to a possible SSL hostname verification bypass, due
to a flaw in comparing the server hostname to the domain name in the Subject's
DN field. A Man In The Middle attack can exploit this vulnerability by using
a specially crafted Subject DN to spoof a valid certificate (CVE-2014-3577).");

  script_tag(name:"affected", value:"'cxf' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"cxf", rpm:"cxf~2.7.5~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cxf-api", rpm:"cxf-api~2.7.5~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cxf-javadoc", rpm:"cxf-javadoc~2.7.5~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cxf-maven-plugins", rpm:"cxf-maven-plugins~2.7.5~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cxf-rt", rpm:"cxf-rt~2.7.5~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cxf-services", rpm:"cxf-services~2.7.5~3.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cxf-tools", rpm:"cxf-tools~2.7.5~3.1.mga4", rls:"MAGEIA4"))) {
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
