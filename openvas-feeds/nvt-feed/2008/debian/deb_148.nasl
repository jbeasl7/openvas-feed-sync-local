# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53727");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2001-1034");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 148-1 (hylafax)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(2\.2|3\.0)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20148-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3357");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5348");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5349");
  script_tag(name:"insight", value:"A set of problems have been discovered in Hylafax, a flexible
client/server fax software distributed with many GNU/Linux
distributions.  Quoting SecurityFocus the problems are in detail:

  * A format string vulnerability makes it possible for users to
potentially execute arbitrary code on some implementations.  Due to
insufficient checking of input, it's possible to execute a format
string attack.  Since this only affects systems with the faxrm and
faxalter programs installed setuid, Debian is not vulnerable.

  * A buffer overflow has been reported in Hylafax.  A malicious fax
transmission may include a long scan line that will overflow a
memory buffer, corrupting adjacent memory.  An exploid may result
in a denial of service condition, or possibly the execution of
arbitrary code with root privileges.

  * A format string vulnerability has been discovered in faxgetty.
Incoming fax messages include a Transmitting Subscriber
Identification (TSI) string, used to identify the sending fax
machine.  Hylafax uses this data as part of a format string without
properly sanitizing the input.  Malicious fax data may cause the
server to crash, resulting in a denial of service condition.

  * Marcin Dawcewicz discovered a format string vulnerability in hfaxd,
which will crash hfaxd under certain circumstances.  Since Debian
doesn't have hfaxd installed setuid root, this problem can not
directly lead into a vulnerability.  This has been fixed by Darren
Nickerson, which was already present in newer versions, but not in
the potato version.

These problems have been fixed in version 4.0.2-14.3 for the old
stable distribution (potato), in version 4.1.1-1.1 for the current
stable distribution (woody) and in version 4.1.2-2.1 for the unstable
distribution (sid).");

  script_tag(name:"solution", value:"We recommend that you upgrade your hylafax packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to hylafax
announced via advisory DSA 148-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"hylafax-doc", ver:"4.0.2-14.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hylafax-client", ver:"4.0.2-14.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hylafax-server", ver:"4.0.2-14.3", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hylafax-doc", ver:"4.1.1-1.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hylafax-client", ver:"4.1.1-1.1", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"hylafax-server", ver:"4.1.1-1.1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
