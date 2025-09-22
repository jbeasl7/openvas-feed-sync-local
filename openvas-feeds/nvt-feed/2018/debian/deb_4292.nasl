# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704292");
  script_cve_id("CVE-2018-16657");
  script_tag(name:"creation_date", value:"2018-09-10 22:00:00 +0000 (Mon, 10 Sep 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-15 17:32:54 +0000 (Thu, 15 Nov 2018)");

  script_name("Debian: Security Advisory (DSA-4292-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DSA-4292-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/DSA-4292-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4292");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/kamailio");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kamailio' package(s) announced via the DSA-4292-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Henning Westerholt discovered a flaw related to the Via header processing in kamailio, a very fast, dynamic and configurable SIP server. An unauthenticated attacker can take advantage of this flaw to mount a denial of service attack via a specially crafted SIP message with an invalid Via header.

For the stable distribution (stretch), this problem has been fixed in version 4.4.4-2+deb9u3.

We recommend that you upgrade your kamailio packages.

For the detailed security status of kamailio please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'kamailio' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kamailio", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-autheph-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-berkeley-bin", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-berkeley-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-carrierroute-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-cnxcc-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-cpl-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-dbg", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-erlang-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-extra-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-geoip-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-ims-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-java-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-json-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-kazoo-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-ldap-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-lua-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-memcached-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-mono-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-mysql-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-outbound-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-perl-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-postgres-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-presence-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-purple-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-python-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-radius-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-redis-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-sctp-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-snmpstats-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-sqlite-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-tls-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-unixodbc-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-utils-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-websocket-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-xml-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kamailio-xmpp-modules", ver:"4.4.4-2+deb9u3", rls:"DEB9"))) {
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
