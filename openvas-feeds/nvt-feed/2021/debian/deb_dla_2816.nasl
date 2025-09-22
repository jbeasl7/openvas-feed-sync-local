# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892816");
  script_cve_id("CVE-2021-32739", "CVE-2021-32743", "CVE-2021-37698");
  script_tag(name:"creation_date", value:"2021-11-18 02:00:11 +0000 (Thu, 18 Nov 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-27 18:36:24 +0000 (Tue, 27 Jul 2021)");

  script_name("Debian: Security Advisory (DLA-2816-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2816-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2816-1");
  script_xref(name:"URL", value:"https://icinga.com/blog/2021/07/15/releasing-icinga-2-12-5-and-2-11-10/#change-ticket-salt");
  script_xref(name:"URL", value:"https://icinga.com/blog/2021/07/15/releasing-icinga-2-12-5-and-2-11-10/#replace-icinga-ca");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/icinga2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icinga2' package(s) announced via the DLA-2816-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Icinga 2, a general-purpose monitoring application. An attacker could retrieve sensitive information such as service passwords and ticket salt by querying the web API, or by intercepting unsufficiently checked encrypted connections.

CVE-2021-32739

A vulnerability exists that may allow privilege escalation for authenticated API users. With a read-only user's credentials, an attacker can view most attributes of all config objects including `ticket_salt` of `ApiListener`. This salt is enough to compute a ticket for every possible common name (CN). A ticket, the master node's certificate, and a self-signed certificate are enough to successfully request the desired certificate from Icinga. That certificate may in turn be used to steal an endpoint or API user's identity. See also complementary manual procedures: [link moved to references] [link moved to references]

CVE-2021-32743

Some of the Icinga 2 features that require credentials for external services expose those credentials through the API to authenticated API users with read permissions for the corresponding object types. IdoMysqlConnection and IdoPgsqlConnection exposes the password of the user used to connect to the database. An attacker who obtains these credentials can impersonate Icinga to these services and add, modify and delete information there. If credentials with more permissions are in use, this increases the impact accordingly.

CVE-2021-37698

InfluxdbWriter and Influxdb2Writer do not verify the server's certificate despite a certificate authority being specified. Icinga 2 instances which connect to any of the mentioned time series databases (TSDBs) using TLS over a spoofable infrastructure should immediately upgrade. Such instances should also change the credentials (if any) used by the TSDB writer feature to authenticate against the TSDB.

For Debian 9 stretch, these problems have been fixed in version 2.6.0-2+deb9u2.

We recommend that you upgrade your icinga2 packages.

For the detailed security status of icinga2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'icinga2' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"icinga2", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icinga2-bin", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icinga2-classicui", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icinga2-common", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icinga2-dbg", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icinga2-doc", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icinga2-ido-mysql", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icinga2-ido-pgsql", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icinga2-studio", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libicinga2", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-icinga2", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
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
