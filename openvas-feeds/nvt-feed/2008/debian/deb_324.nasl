# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53613");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0428", "CVE-2003-0429", "CVE-2003-0431", "CVE-2003-0432");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 324-1 (ethereal)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20324-1");
  script_xref(name:"URL", value:"http://www.ethereal.com/appnotes/enpa-sa-00010.html");
  script_tag(name:"insight", value:"Several of the packet dissectors in ethereal contain string handling
bugs which could be exploited using a maliciously crafted packet to
cause ethereal to consume excessive amounts of memory, crash, or
execute arbitrary code.

These vulnerabilities were announced in the referenced Ethereal security
advisory.

Ethereal 0.9.4 in Debian 3.0 (woody) is affected by most of the
problems described in the advisory, including:

  * The DCERPC dissector could try to allocate too much memory
while trying to decode an NDR string.

  * Bad IPv4 or IPv6 prefix lengths could cause an overflow in the
OSI dissector.

  * The tvb_get_nstringz0() routine incorrectly handled a
zero-length buffer size.

  * The BGP, WTP, DNS, 802.11, ISAKMP, WSP, CLNP, and ISIS
dissectors handled strings improperly.

The following problems do NOT affect this version:

  * The SPNEGO dissector could segfault while parsing an invalid
ASN.1 value.

  * The RMI dissector handled strings improperly

as these modules are not present.

For the stable distribution (woody) these problems have been fixed in
version 0.9.4-1woody5.

The old stable distribution (potato) these problems will be fixed in a
future advisory.

For the unstable distribution (sid) these problems are fixed in
version 0.9.13-1.

We recommend that you update your ethereal package.");
  script_tag(name:"summary", value:"The remote host is missing an update to ethereal
announced via advisory DSA 324-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ethereal", ver:"0.9.4-1woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ethereal-common", ver:"0.9.4-1woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.9.4-1woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tethereal", ver:"0.9.4-1woody5", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
