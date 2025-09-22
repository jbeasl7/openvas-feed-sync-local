# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703176");
  script_cve_id("CVE-2014-9472", "CVE-2015-1165", "CVE-2015-1464");
  script_tag(name:"creation_date", value:"2015-02-25 23:00:00 +0000 (Wed, 25 Feb 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-3176-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3176-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3176-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3176");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'request-tracker4' package(s) announced via the DSA-3176-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Request Tracker, an extensible trouble-ticket tracking system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-9472

Christian Loos discovered a remote denial of service vulnerability, exploitable via the email gateway and affecting any installation which accepts mail from untrusted sources. Depending on RT's logging configuration, a remote attacker can take advantage of this flaw to cause CPU and excessive disk usage.

CVE-2015-1165

Christian Loos discovered an information disclosure flaw which may reveal RSS feeds URLs, and thus ticket data.

CVE-2015-1464

It was discovered that RSS feed URLs can be leveraged to perform session hijacking, allowing a user with the URL to log in as the user that created the feed.

For the stable distribution (wheezy), these problems have been fixed in version 4.0.7-5+deb7u3.

For the unstable distribution (sid), these problems have been fixed in version 4.2.8-3.

We recommend that you upgrade your request-tracker4 packages.");

  script_tag(name:"affected", value:"'request-tracker4' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.0.7-5+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.0.7-5+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.0.7-5+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.0.7-5+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.0.7-5+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.0.7-5+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.0.7-5+deb7u3", rls:"DEB7"))) {
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
