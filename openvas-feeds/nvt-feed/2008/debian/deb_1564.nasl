# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60930");
  script_cve_id("CVE-2007-0540", "CVE-2007-3639", "CVE-2007-4153", "CVE-2007-4154", "CVE-2008-2146");
  script_tag(name:"creation_date", value:"2008-05-12 17:53:28 +0000 (Mon, 12 May 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1564-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1564-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1564-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1564");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-1564-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in WordPress, a weblog manager. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3639

Insufficient input sanitising allowed for remote attackers to redirect visitors to external websites.

CVE-2007-4153

Multiple cross-site scripting vulnerabilities allowed remote authenticated administrators to inject arbitrary web script or HTML.

CVE-2007-4154

SQL injection vulnerability allowed allowed remote authenticated administrators to execute arbitrary SQL commands.

CVE-2007-0540

WordPress allows remote attackers to cause a denial of service (bandwidth or thread consumption) via pingback service calls with a source URI that corresponds to a file with a binary content type, which is downloaded even though it cannot contain usable pingback data.

[no CVE name yet] Insufficient input sanitising caused an attacker with a normal user account to access the administrative interface.

For the stable distribution (etch), these problems have been fixed in version 2.0.10-1etch2.

For the unstable distribution (sid), these problems have been fixed in version 2.2.3-1.

We recommend that you upgrade your wordpress package.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"wordpress", ver:"2.0.10-1etch2", rls:"DEB4"))) {
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
