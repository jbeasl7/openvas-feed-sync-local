# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53132");
  script_cve_id("CVE-2004-0005", "CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-16 20:47:22 +0000 (Fri, 16 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-434)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-434");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-434");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-434");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gaim' package(s) announced via the DSA-434 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Esser discovered several security related problems in Gaim, a multi-protocol instant messaging client. Not all of them are applicable for the version in Debian stable, but affected the version in the unstable distribution at least. The problems were grouped for the Common Vulnerabilities and Exposures as follows:

CAN-2004-0005

When the Yahoo Messenger handler decodes an octal value for email notification functions two different kinds of overflows can be triggered. When the MIME decoder decoded a quoted printable encoded string for email notification two other different kinds of overflows can be triggered. These problems only affect the version in the unstable distribution.

CAN-2004-0006

When parsing the cookies within the HTTP reply header of a Yahoo web connection a buffer overflow can happen. When parsing the Yahoo Login Webpage the YMSG protocol overflows stack buffers if the web page returns oversized values. When splitting a URL into its parts a stack overflow can be caused. These problems only affect the version in the unstable distribution.

When an oversized keyname is read from a Yahoo Messenger packet a stack overflow can be triggered. When Gaim is setup to use an HTTP proxy for connecting to the server a malicious HTTP proxy can exploit it. These problems affect all versions Debian ships. However, the connection to Yahoo doesn't work in the version in Debian stable.

CAN-2004-0007

Internally data is copied between two tokens into a fixed size stack buffer without a size check. This only affects the version of gaim in the unstable distribution.

CAN-2004-0008

When allocating memory for AIM/Oscar DirectIM packets an integer overflow can happen, resulting in a heap overflow. This only affects the version of gaim in the unstable distribution.

For the stable distribution (woody) these problems has been fixed in version 0.58-2.4.

For the unstable distribution (sid) these problems has been fixed in version 0.75-2.

We recommend that you upgrade your gaim packages.");

  script_tag(name:"affected", value:"'gaim' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gaim", ver:"1:0.58-2.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gaim-common", ver:"1:0.58-2.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gaim-gnome", ver:"1:0.58-2.4", rls:"DEB3.0"))) {
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
