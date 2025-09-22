# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0064");
  script_cve_id("CVE-2013-5679");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0064)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0064");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0064.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15254");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-January/148081.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'owasp-esapi-java' package(s) announced via the MGASA-2015-0064 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated owasp-esapi-java packages fix security vulnerability:

The authenticated-encryption feature in the symmetric-encryption
implementation in the OWASP Enterprise Security API (ESAPI) for Java 2.x
before 2.1.0 does not properly resist tampering with serialized ciphertext,
which makes it easier for remote attackers to bypass intended cryptographic
protection mechanisms via an attack against authenticity in the default
configuration, involving a null MAC and a zero MAC length (CVE-2013-5679).");

  script_tag(name:"affected", value:"'owasp-esapi-java' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"owasp-esapi-java", rpm:"owasp-esapi-java~2.1.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"owasp-esapi-java-doc", rpm:"owasp-esapi-java-doc~2.1.0~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"owasp-esapi-java-javadoc", rpm:"owasp-esapi-java-javadoc~2.1.0~1.mga4", rls:"MAGEIA4"))) {
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
