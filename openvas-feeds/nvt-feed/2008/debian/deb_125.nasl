# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53578");
  script_cve_id("CVE-2002-0166");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 125-1 (analog)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20125-1");
  script_tag(name:"insight", value:"Yuji Takahashi discovered a bug in analog which allows a cross-site
scripting type attack.  It is easy for an attacker to insert arbitrary
strings into any web server logfile.  If these strings are then
analysed by analog, they can appear in the report.  By this means an
attacker can introduce arbitrary Javascript code, for example, into an
analog report produced by someone else and read by a third person.
Analog already attempted to encode unsafe characters to avoid this
type of attack, but the conversion was incomplete.

This problem has been fixed in the upstream version 5.22 of analog.
Unfortunately patching the old version of analog in the stable
distribution of Debian instead is a very large job that defeats us.");

  script_tag(name:"solution", value:"We recommend that you upgrade your analog package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to analog
announced via advisory DSA 125-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"analog", ver:"5.22-0potato1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
