# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53375");
  script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:23:34 +0000 (Fri, 02 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-394)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-394");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-394");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-394");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl095' package(s) announced via the DSA-394 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steve Henson of the OpenSSL core team identified and prepared fixes for a number of vulnerabilities in the OpenSSL ASN1 code that were discovered after running a test suite by British National Infrastructure Security Coordination Centre (NISCC).

A bug in OpenSSLs SSL/TLS protocol was also identified which causes OpenSSL to parse a client certificate from an SSL/TLS client when it should reject it as a protocol error.

The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2003-0543: Integer overflow in OpenSSL that allows remote attackers to cause a denial of service (crash) via an SSL client certificate with certain ASN.1 tag values. CAN-2003-0544: OpenSSL does not properly track the number of characters in certain ASN.1 inputs, which allows remote attackers to cause a denial of service (crash) via an SSL client certificate that causes OpenSSL to read past the end of a buffer when the long form is used. CAN-2003-0545: Double-free vulnerability allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via an SSL client certificate with a certain invalid ASN.1 encoding. This bug was only present in OpenSSL 0.9.7 and is listed here only for reference.

For the stable distribution (woody) this problem has been fixed in openssl095 version 0.9.5a-6.woody.3.

This package is not present in the unstable (sid) or testing (sarge) distribution.

We recommend that you upgrade your libssl095a packages and restart services using this library. Debian doesn't ship any packages that are linked against this library.

The following commandline (courtesy of Ray Dassen) produces a list of names of running processes that have libssl095 mapped into their memory space:

find /proc -name maps -exec egrep -l 'libssl095' {} /dev/null , <pipe> sed -e 's/[^0-9]//g' <pipe> xargs --no-run-if-empty ps --no-headers -p <pipe> sed -e 's/^+//' -e 's/ +/ /g' <pipe> cut -d ' ' -f 5 <pipe> sort <pipe> uniq

You should restart the associated services.");

  script_tag(name:"affected", value:"'openssl095' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl095a", ver:"0.9.5a-6.woody.3", rls:"DEB3.0"))) {
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
