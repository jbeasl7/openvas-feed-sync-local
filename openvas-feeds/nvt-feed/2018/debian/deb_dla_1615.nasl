# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891615");
  script_cve_id("CVE-2013-7108", "CVE-2013-7205", "CVE-2014-1878", "CVE-2016-9566", "CVE-2018-18245");
  script_tag(name:"creation_date", value:"2018-12-27 23:00:00 +0000 (Thu, 27 Dec 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-16 19:10:38 +0000 (Fri, 16 Dec 2016)");

  script_name("Debian: Security Advisory (DLA-1615-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1615-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1615-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nagios3' package(s) announced via the DLA-1615-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues were corrected in nagios3, a monitoring and management system for hosts, services and networks.

CVE-2018-18245

Maximilian Boehner of usd AG found a cross-site scripting (XSS) vulnerability in Nagios Core. This vulnerability allows attackers to place malicious JavaScript code into the web frontend through manipulation of plugin output. In order to do this the attacker needs to be able to manipulate the output returned by nagios checks, e.g. by replacing a plugin on one of the monitored endpoints. Execution of the payload then requires that an authenticated user creates an alert summary report which contains the corresponding output.

CVE-2016-9566

It was discovered that local users with access to an account in the nagios group are able to gain root privileges via a symlink attack on the debug log file.

CVE-2014-1878

An issue was corrected that allowed remote attackers to cause a stack-based buffer overflow and subsequently a denial of service (segmentation fault) via a long message to cmd.cgi.

CVE-2013-7205 / CVE-2013-7108 A flaw was corrected in Nagios that could be exploited to cause a denial-of-service. This vulnerability is induced due to an off-by-one error within the process_cgivars() function, which can be exploited to cause an out-of-bounds read by sending a specially-crafted key value to the Nagios web UI.

For Debian 8 Jessie, these problems have been fixed in version 3.5.1.dfsg-2+deb8u1.

We recommend that you upgrade your nagios3 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'nagios3' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"nagios3", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-cgi", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-common", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-core", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-dbg", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-doc", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8"))) {
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
