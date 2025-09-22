# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703154");
  script_cve_id("CVE-2014-9750", "CVE-2014-9751");
  script_tag(name:"creation_date", value:"2015-02-04 23:00:00 +0000 (Wed, 04 Feb 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3154-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3154-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3154-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3154");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ntp' package(s) announced via the DSA-3154-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the ntp package, an implementation of the Network Time Protocol. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-9750

Stephen Roettger of the Google Security Team, Sebastian Krahmer of the SUSE Security Team and Harlan Stenn of Network Time Foundation discovered that the length value in extension fields is not properly validated in several code paths in ntp_crypto.c, which could lead to information leakage or denial of service (ntpd crash).

CVE-2014-9751

Stephen Roettger of the Google Security Team reported that ACLs based on IPv6 ::1 addresses can be bypassed.

For the stable distribution (wheezy), these problems have been fixed in version 1:4.2.6.p5+dfsg-2+deb7u2.

For the unstable distribution (sid), these problems have been fixed in version 1:4.2.6.p5+dfsg-4.

We recommend that you upgrade your ntp packages.");

  script_tag(name:"affected", value:"'ntp' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p5+dfsg-2+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p5+dfsg-2+deb7u3", rls:"DEB7"))) {
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
