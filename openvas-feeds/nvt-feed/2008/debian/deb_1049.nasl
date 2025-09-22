# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56670");
  script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1049-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-1049-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1049-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1049");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ethereal' package(s) announced via the DSA-1049-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gerald Combs reported several vulnerabilities in ethereal, a popular network traffic analyser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-1932

The OID printing routine is susceptible to an off-by-one error.

CVE-2006-1933

The UMA and BER dissectors could go into an infinite loop.

CVE-2006-1934

The Network Instruments file code could overrun a buffer.

CVE-2006-1935

The COPS dissector contains a potential buffer overflow.

CVE-2006-1936

The telnet dissector contains a buffer overflow.

CVE-2006-1937

Bugs in the SRVLOC and AIM dissector, and in the statistics counter could crash ethereal.

CVE-2006-1938

Null pointer dereferences in the SMB PIPE dissector and when reading a malformed Sniffer capture could crash ethereal.

CVE-2006-1939

Null pointer dereferences in the ASN.1, GSM SMS, RPC and ASN.1-based dissector and an invalid display filter could crash ethereal.

CVE-2006-1940

The SNDCP dissector could cause an unintended abortion.

For the old stable distribution (woody) these problems have been fixed in version 0.9.4-1woody15.

For the stable distribution (sarge) these problems have been fixed in version 0.10.10-2sarge5.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your ethereal packages.");

  script_tag(name:"affected", value:"'ethereal' package(s) on Debian 3.0, Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ethereal", ver:"0.9.4-1woody15", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-common", ver:"0.9.4-1woody15", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.9.4-1woody15", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tethereal", ver:"0.9.4-1woody15", rls:"DEB3.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"ethereal", ver:"0.10.10-2sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-common", ver:"0.10.10-2sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.10.10-2sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tethereal", ver:"0.10.10-2sarge5", rls:"DEB3.1"))) {
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
