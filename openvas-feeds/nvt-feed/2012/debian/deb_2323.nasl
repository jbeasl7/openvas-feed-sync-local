# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70546");
  script_cve_id("CVE-2011-3601", "CVE-2011-3602", "CVE-2011-3604", "CVE-2011-3605");
  script_tag(name:"creation_date", value:"2012-02-11 07:27:04 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2323-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2323-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2323-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2323");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'radvd' package(s) announced via the DSA-2323-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered by Vasiliy Kulikov in radvd, an IPv6 Router Advertisement daemon:

CVE-2011-3602

set_interface_var() function doesn't check the interface name, which is chosen by an unprivileged user. This could lead to an arbitrary file overwrite if the attacker has local access, or specific files overwrites otherwise.

CVE-2011-3604

process_ra() function lacks multiple buffer length checks which could lead to memory reads outside the stack, causing a crash of the daemon.

CVE-2011-3605

process_rs() function calls mdelay() (a function to wait for a defined time) unconditionally when running in unicast-only mode. As this call is in the main thread, that means all request processing is delayed (for a time up to MAX_RA_DELAY_TIME, 500 ms by default). An attacker could flood the daemon with router solicitations in order to fill the input queue, causing a temporary denial of service (processing would be stopped during all the mdelay() calls). Note: upstream and Debian default is to use anycast mode.

For the oldstable distribution (lenny), this problem has been fixed in version 1:1.1-3.1.

For the stable distribution (squeeze), this problem has been fixed in version 1:1.6-1.1.

For the testing distribution (wheezy), this problem has been fixed in version 1:1.8-1.2.

For the unstable distribution (sid), this problem has been fixed in version 1:1.8-1.2.

We recommend that you upgrade your radvd packages.");

  script_tag(name:"affected", value:"'radvd' package(s) on Debian 5, Debian 6.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"radvd", ver:"1:1.1-3.1", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"radvd", ver:"1:1.6-1.1", rls:"DEB6"))) {
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
