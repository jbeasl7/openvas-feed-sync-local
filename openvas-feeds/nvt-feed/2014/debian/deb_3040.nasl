# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703040");
  script_cve_id("CVE-2014-3634");
  script_tag(name:"creation_date", value:"2014-09-29 22:00:00 +0000 (Mon, 29 Sep 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3040-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3040-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3040-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3040");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rsyslog' package(s) announced via the DSA-3040-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rainer Gerhards, the rsyslog project leader, reported a vulnerability in Rsyslog, a system for log processing. As a consequence of this vulnerability an attacker can send malformed messages to a server, if this one accepts data from untrusted sources, and trigger a denial of service attack.

For the stable distribution (wheezy), this problem has been fixed in version 5.8.11-3+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 8.4.1-1.

We recommend that you upgrade your rsyslog packages.");

  script_tag(name:"affected", value:"'rsyslog' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog", ver:"5.8.11-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-doc", ver:"5.8.11-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-gnutls", ver:"5.8.11-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-gssapi", ver:"5.8.11-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-mysql", ver:"5.8.11-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-pgsql", ver:"5.8.11-3+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rsyslog-relp", ver:"5.8.11-3+deb7u1", rls:"DEB7"))) {
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
