# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61172");
  script_cve_id("CVE-2007-5824", "CVE-2007-5825", "CVE-2008-1771");
  script_tag(name:"creation_date", value:"2008-06-27 22:42:46 +0000 (Fri, 27 Jun 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1597-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1597-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1597-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1597");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mt-daapd' package(s) announced via the DSA-1597-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Three vulnerabilities have been discovered in the mt-daapd DAAP audio server (also known as the Firefly Media Server). The Common Vulnerabilities and Exposures project identifies the following three problems:

CVE-2007-5824

Insufficient validation and bounds checking of the Authorization: HTTP header enables a heap buffer overflow, potentially enabling the execution of arbitrary code.

CVE-2007-5825

Format string vulnerabilities in debug logging within the authentication of XML-RPC requests could enable the execution of arbitrary code.

CVE-2008-1771

An integer overflow weakness in the handling of HTTP POST variables could allow a heap buffer overflow and potentially arbitrary code execution.

For the stable distribution (etch), these problems have been fixed in version 0.2.4+r1376-1.1+etch2.

For the unstable distribution (sid), these problems have been fixed in version 0.9~r1696-1.4.

We recommend that you upgrade your mt-daapd package.");

  script_tag(name:"affected", value:"'mt-daapd' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mt-daapd", ver:"0.2.4+r1376-1.1+etch1", rls:"DEB4"))) {
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
