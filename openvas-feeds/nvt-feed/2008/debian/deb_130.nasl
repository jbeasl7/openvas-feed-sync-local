# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53847");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0353");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 130-1 (ethereal)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20130-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4604");
  script_tag(name:"insight", value:"Ethereal versions prior to 0.9.3 were vulnerable to an allocation error
in the ASN.1 parser. This can be triggered when analyzing traffic using
the SNMP, LDAP, COPS, or Kerberos protocols in ethereal. This
vulnerability was announced in the ethereal security advisory
enpa-sa-00003 and has been given the proposed CVE id of CVE-2002-0353.
This issue has been corrected in ethereal version 0.8.0-3potato for
Debian 2.2 (potato).

Additionally, a number of vulnerabilities were discussed in ethereal
security advisory enpa-sa-00004. The version of ethereal in Debian 2.2
(potato) is not vulnerable to the issues raised in this later advisory.
Users of the not-yet-released woody distribution should ensure that they
are running ethereal 0.9.4-1 or a later version.

We recommend you upgrade your ethereal package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to ethereal
announced via advisory DSA 130-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ethereal", ver:"0.8.0-3potato", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
