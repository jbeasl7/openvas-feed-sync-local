# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71248");
  script_cve_id("CVE-2010-5077");
  script_tag(name:"creation_date", value:"2012-04-30 11:55:33 +0000 (Mon, 30 Apr 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2442-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2442-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2442-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2442");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openarena' package(s) announced via the DSA-2442-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that spoofed getstatus UDP requests are being sent by attackers to servers for use with games derived from the Quake 3 engine (such as openarena). These servers respond with a packet flood to the victim whose IP address was impersonated by the attackers, causing a denial of service.

For the stable distribution (squeeze), this problem has been fixed in version 0.8.5-5+squeeze3.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 0.8.5-6.

We recommend that you upgrade your openarena packages.");

  script_tag(name:"affected", value:"'openarena' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openarena", ver:"0.8.5-5+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openarena-server", ver:"0.8.5-5+squeeze3", rls:"DEB6"))) {
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
