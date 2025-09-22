# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704142");
  script_cve_id("CVE-2018-7490");
  script_tag(name:"creation_date", value:"2018-03-16 23:00:00 +0000 (Fri, 16 Mar 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-23 15:24:38 +0000 (Fri, 23 Mar 2018)");

  script_name("Debian: Security Advisory (DSA-4142-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4142-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4142-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4142");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/uwsgi");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'uwsgi' package(s) announced via the DSA-4142-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marios Nicolaides discovered that the PHP plugin in uWSGI, a fast, self-healing application container server, does not properly handle a DOCUMENT_ROOT check during use of the --php-docroot option, allowing a remote attacker to mount a directory traversal attack and gain unauthorized read access to sensitive files located outside of the web root directory.

For the oldstable distribution (jessie), this problem has been fixed in version 2.0.7-1+deb8u2. This update additionally includes the fix for CVE-2018-6758 which was aimed to be addressed in the upcoming jessie point release.

For the stable distribution (stretch), this problem has been fixed in version 2.0.14+20161117-3+deb9u2.

We recommend that you upgrade your uwsgi packages.

For the detailed security status of uwsgi please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'uwsgi' package(s) on Debian 8, Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi-dbg", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi-dbg", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-uwsgi", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-uwsgi-dbg", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-uwsgidecorators", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-uwsgidecorators", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-app-integration-plugins", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-core", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-dbg", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-emperor", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-extra", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-infrastructure-plugins", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-curl", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-xmpp", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-curl-cron", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-emperor-pg", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-fiber", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-geoip", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-graylog2", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-greenlet-python", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-jvm-openjdk-7", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-jwsgi-openjdk-7", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-ldap", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.1", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.2", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-luajit", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-php", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-psgi", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-python", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-python3", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rack-ruby2.1", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rados", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rbthreads", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-router-access", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-sqlite3", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-v8", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-xslt", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugins-all", ver:"2.0.7-1+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi-dbg", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-uwsgi", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-uwsgidecorators", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-uwsgidecorators", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-app-integration-plugins", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-core", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-emperor", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-extra", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-infrastructure-plugins", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-mongodb-plugins", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-curl", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-xmpp", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-asyncio-python", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-asyncio-python3", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-curl-cron", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-emperor-pg", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-fiber", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-gccgo", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-geoip", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-gevent-python", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-glusterfs", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-graylog2", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-greenlet-python", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-jvm-openjdk-8", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-jwsgi-openjdk-8", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-ldap", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.1", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.2", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-luajit", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-mono", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-php", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-psgi", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-python", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-python3", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rack-ruby2.3", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rados", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rbthreads", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-ring-openjdk-8", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-router-access", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-servlet-openjdk-8", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-sqlite3", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-tornado-python", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-v8", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-xslt", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugins-all", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-src", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9"))) {
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
