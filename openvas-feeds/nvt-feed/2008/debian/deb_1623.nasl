# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61375");
  script_cve_id("CVE-2008-1447");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2008-07-09 15:22:00 +0000 (Wed, 09 Jul 2008)");

  script_name("Debian: Security Advisory (DSA-1623-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1623-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1623-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1623");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dnsmasq' package(s) announced via the DSA-1623-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Kaminsky discovered that properties inherent to the DNS protocol lead to practical DNS cache poisoning attacks. Among other things, successful attacks can lead to misdirected web traffic and email rerouting.

This update changes Debian's dnsmasq packages to implement the recommended countermeasure: UDP query source port randomization. This change increases the size of the space from which an attacker has to guess values in a backwards-compatible fashion and makes successful attacks significantly more difficult.

This update also switches the random number generator to Dan Bernstein's SURF.

For the stable distribution (etch), this problem has been fixed in version 2.35-1+etch4. Packages for alpha will be provided later.

For the unstable distribution (sid), this problem has been fixed in version 2.43-1.

We recommend that you upgrade your dnsmasq package.");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"dnsmasq", ver:"2.35-1+etch4", rls:"DEB4"))) {
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
