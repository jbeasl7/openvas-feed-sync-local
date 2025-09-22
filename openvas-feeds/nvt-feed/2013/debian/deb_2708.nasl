# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702708");
  script_cve_id("CVE-2013-2178");
  script_tag(name:"creation_date", value:"2013-06-15 22:00:00 +0000 (Sat, 15 Jun 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2708-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2708-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2708-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2708");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fail2ban' package(s) announced via the DSA-2708-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Krzysztof Katowicz-Kowalewski discovered a vulnerability in Fail2ban, a log monitoring and system which can act on attack by preventing hosts to connect to specified services using the local firewall.

When using Fail2ban to monitor Apache logs, improper input validation in log parsing could enable a remote attacker to trigger an IP ban on arbitrary addresses, thus causing a denial of service.

For the oldstable distribution (squeeze), this problem has been fixed in version 0.8.4-3+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in version 0.8.6-3wheezy2.

For the testing distribution (jessie), this problem has been fixed in version 0.8.10-1.

For the unstable distribution (sid), this problem has been fixed in version 0.8.10-1.

We recommend that you upgrade your fail2ban packages.");

  script_tag(name:"affected", value:"'fail2ban' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"fail2ban", ver:"0.8.4-3+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"fail2ban", ver:"0.8.6-3wheezy2", rls:"DEB7"))) {
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
