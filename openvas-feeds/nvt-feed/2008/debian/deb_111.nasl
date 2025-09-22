# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53841");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 111-1 (ucd-snmp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20111-1");
  script_tag(name:"insight", value:"The Secure Programming Group of the Oulu University did a study on
SNMP implementations and uncovered multiple problems which can
cause problems ranging from Denial of Service attacks to remote
exploits.

New UCD-SNMP packages have been prepared to fix these problems
as well as a few others. The complete list of fixed problems is:

  * When running external programs snmpd used temporary files insecurely

  * snmpd did not properly reset supplementary groups after changing
its uid and gid

  * Modified most code to use buffers instead of fixed-length strings to
prevent buffer overflows

  * The ASN.1 parser did not check for negative lengths

  * the IFINDEX response handling in snmpnetstat did not do a sanity check
on its input

(thanks to Caldera for most of the work on those patches)

The new version is 4.1.1-2.1 and we recommend you upgrade your
snmp packages immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to ucd-snmp
announced via advisory DSA 111-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libsnmp4.1-dev", ver:"4.1.1-2.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsnmp4.1", ver:"4.1.1-2.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"snmp", ver:"4.1.1-2.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"snmpd", ver:"4.1.1-2.1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
