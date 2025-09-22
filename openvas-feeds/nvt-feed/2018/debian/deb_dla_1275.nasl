# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891275");
  script_cve_id("CVE-2018-6758");
  script_tag(name:"creation_date", value:"2018-02-20 23:00:00 +0000 (Tue, 20 Feb 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-01 15:06:42 +0000 (Thu, 01 Mar 2018)");

  script_name("Debian: Security Advisory (DLA-1275-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1275-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1275-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'uwsgi' package(s) announced via the DLA-1275-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the uwsgi_expand_path function in utils.c in Unbit uWSGI, an application container server, has a stack-based buffer overflow via a large directory length that can cause a denial-of-service (application crash) or stack corruption.

For Debian 7 Wheezy, these problems have been fixed in version 1.2.3+dfsg-5+deb7u2.

We recommend that you upgrade your uwsgi packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'uwsgi' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi-dbg", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-uwsgi", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-uwsgi-dbg", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-django-uwsgi-admin", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-uwsgicc", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-uwsgidecorators", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-uwsgidecorators", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-app-integration-plugins", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-core", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-dbg", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-extra", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-infrastructure-plugins", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-admin", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-cache", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-carbon", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-cgi", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-echo", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-erlang", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-fastrouter", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-fiber", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-graylog2", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-greenlet-python", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-http", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-jvm-openjdk-6", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-jwsgi-openjdk-6", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-logsocket", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.1", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-nagios", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-ping", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-probeconnect", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-probepg", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-psgi", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-pyerl-python", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-pyerl-python3", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-python", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-python3", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rack-ruby1.8", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rack-ruby1.9.1", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rpc", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rrdtool", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rsyslog", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-signal", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-symcall", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-syslog", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-ugreen", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugins-all", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7"))) {
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
