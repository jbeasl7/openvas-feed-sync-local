# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0193");
  script_cve_id("CVE-2013-2153", "CVE-2013-2154", "CVE-2013-2155", "CVE-2013-2156", "CVE-2013-2210");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-01T14:37:12+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:12 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0193");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0193.html");
  script_xref(name:"URL", value:"http://santuario.apache.org/secadv.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2710");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10563");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xml-security-c' package(s) announced via the MGASA-2013-0193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The implementation of XML digital signatures in the Santuario-C++ library
is vulnerable to a spoofing issue allowing an attacker to reuse existing
signatures with arbitrary content (CVE-2013-2153).

A stack overflow, possibly leading to arbitrary code execution, exists in
the processing of malformed XPointer expressions in the XML Signature
Reference processing code (CVE-2013-2154).

A bug in the processing of the output length of an HMAC-based XML
Signature would cause a denial of service when processing specially chosen
input (CVE-2013-2155).

A heap overflow exists in the processing of the PrefixList attribute
optionally used in conjunction with Exclusive Canonicalization, potentially
allowing arbitrary code execution (CVE-2013-2156).

The attempted fix to address CVE-2013-2154 introduced the possibility of a
heap overflow, possibly leading to arbitrary code execution, in the
processing of malformed XPointer expressions in the XML Signature Reference
processing code (CVE-2013-2210).");

  script_tag(name:"affected", value:"'xml-security-c' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"xml-security-c", rpm:"xml-security-c~1.6.1~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xml-security-c-devel", rpm:"xml-security-c-devel~1.6.1~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"xml-security-c", rpm:"xml-security-c~1.7.0~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xml-security-c-devel", rpm:"xml-security-c-devel~1.7.0~2.2.mga3", rls:"MAGEIA3"))) {
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
