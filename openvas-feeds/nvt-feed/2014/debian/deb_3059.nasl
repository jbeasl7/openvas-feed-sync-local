# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703059");
  script_cve_id("CVE-2014-8761", "CVE-2014-8762", "CVE-2014-8763", "CVE-2014-8764");
  script_tag(name:"creation_date", value:"2014-10-28 23:00:00 +0000 (Tue, 28 Oct 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3059-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3059-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-3059-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3059");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dokuwiki' package(s) announced via the DSA-3059-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in dokuwiki. Access control in the media manager was insufficiently restricted and authentication could be bypassed when using Active Directory for LDAP authentication.

For the stable distribution (wheezy), these problems have been fixed in version 0.0.20120125b-2+deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 0.0.20140929.a-1.

We recommend that you upgrade your dokuwiki packages.");

  script_tag(name:"affected", value:"'dokuwiki' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dokuwiki", ver:"0.0.20120125b-2+deb7u1", rls:"DEB7"))) {
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
