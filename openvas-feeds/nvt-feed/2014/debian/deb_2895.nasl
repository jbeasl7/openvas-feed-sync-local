# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702895");
  script_cve_id("CVE-2014-2744", "CVE-2014-2745");
  script_tag(name:"creation_date", value:"2014-04-05 22:00:00 +0000 (Sat, 05 Apr 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2895-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2895-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2895-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2895");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'prosody' package(s) announced via the DSA-2895-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial-of-service vulnerability has been reported in Prosody, a XMPP server. If compression is enabled, an attacker might send highly-compressed XML elements (attack known as zip bomb) over XMPP streams and consume all the resources of the server.

The SAX XML parser lua-expat is also affected by this issue.

For the stable distribution (wheezy), this problem has been fixed in version 0.8.2-4+deb7u1 of prosody.

For the unstable distribution (sid), this problem has been fixed in version 0.9.4-1 of prosody.

For the stable distribution (wheezy), this problem has been fixed in version 1.2.0-5+deb7u1 of lua-expat.

For the unstable distribution (sid), this problem has been fixed in version 1.3.0-1 lua-expat.

We recommend that you upgrade your prosody and lua-expat packages.");

  script_tag(name:"affected", value:"'prosody' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"prosody", ver:"0.8.2-4+deb7u1", rls:"DEB7"))) {
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
