# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61936");
  script_cve_id("CVE-2008-3137", "CVE-2008-3138", "CVE-2008-3141", "CVE-2008-3145", "CVE-2008-3933", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685");
  script_tag(name:"creation_date", value:"2008-12-03 17:25:22 +0000 (Wed, 03 Dec 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1673-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1673-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1673-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1673");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wireshark' package(s) announced via the DSA-1673-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in network traffic analyzer Wireshark. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-3137

The GSM SMS dissector is vulnerable to denial of service.

CVE-2008-3138

The PANA and KISMET dissectors are vulnerable to denial of service.

CVE-2008-3141

The RMI dissector could disclose system memory.

CVE-2008-3145

The packet reassembling module is vulnerable to denial of service.

CVE-2008-3933

The zlib uncompression module is vulnerable to denial of service.

CVE-2008-4683

The Bluetooth ACL dissector is vulnerable to denial of service.

CVE-2008-4684

The PRP and MATE dissectors are vulnerable to denial of service.

CVE-2008-4685

The Q931 dissector is vulnerable to denial of service.

For the stable distribution (etch), these problems have been fixed in version 0.99.4-5.etch.3.

For the upcoming stable distribution (lenny), these problems have been fixed in version 1.0.2-3+lenny2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your wireshark packages.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"ethereal", ver:"0.99.4-5.etch.3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-common", ver:"0.99.4-5.etch.3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.99.4-5.etch.3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tethereal", ver:"0.99.4-5.etch.3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"0.99.4-5.etch.3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"0.99.4-5.etch.3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"0.99.4-5.etch.3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-dev", ver:"0.99.4-5.etch.3", rls:"DEB4"))) {
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
