# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64822");
  script_cve_id("CVE-2008-7159", "CVE-2008-7160", "CVE-2009-3051", "CVE-2009-3163");
  script_tag(name:"creation_date", value:"2009-09-09 00:15:49 +0000 (Wed, 09 Sep 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1879-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1879-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1879-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1879");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'silc-client, silc-toolkit' package(s) announced via the DSA-1879-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the software suite for the SILC protocol, a network protocol designed to provide end-to-end security for conferencing services. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-7159

An incorrect format string in sscanf() used in the ASN1 encoder to scan an OID value could overwrite a neighbouring variable on the stack as the destination data type is smaller than the source type on 64-bit. On 64-bit architectures this could result in unexpected application behaviour or even code execution in some cases.

CVE-2009-3051

Various format string vulnerabilities when handling parsed SILC messages allow an attacker to execute arbitrary code with the rights of the victim running the SILC client via crafted nick names or channel names containing format strings.

CVE-2008-7160

An incorrect format string in a sscanf() call used in the HTTP server component of silcd could result in overwriting a neighbouring variable on the stack as the destination data type is smaller than the source type on 64-bit. An attacker could exploit this by using crafted Content-Length header values resulting in unexpected application behaviour or even code execution in some cases.

silc-server doesn't need an update as it uses the shared library provided by silc-toolkit. silc-client/silc-toolkit in the oldstable distribution (etch) is not affected by this problem.

For the stable distribution (lenny), this problem has been fixed in version 1.1.7-2+lenny1 of silc-toolkit and in version 1.1.4-1+lenny1 of silc-client.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.1.10-1 of silc-toolkit and version 1.1-2 of silc-client (using libsilc from silc-toolkit since this upload).

We recommend that you upgrade your silc-toolkit/silc-client packages.");

  script_tag(name:"affected", value:"'silc-client, silc-toolkit' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"irssi-plugin-silc", ver:"1.1.4-1+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsilc-1.1-2", ver:"1.1.7-2+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsilc-1.1-2-dbg", ver:"1.1.7-2+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsilc-1.1-2-dev", ver:"1.1.7-2+lenny1", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"silc", ver:"1.1.4-1+lenny1", rls:"DEB5"))) {
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
