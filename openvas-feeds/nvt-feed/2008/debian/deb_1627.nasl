# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61590");
  script_cve_id("CVE-2008-2235", "CVE-2008-3972");
  script_tag(name:"creation_date", value:"2008-09-17 02:23:15 +0000 (Wed, 17 Sep 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1627-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1627-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1627-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1627");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'opensc' package(s) announced via the DSA-1627-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chaskiel M Grundman discovered that opensc, a library and utilities to handle smart cards, would initialise smart cards with the Siemens CardOS M4 card operating system without proper access rights. This allowed everyone to change the card's PIN.

With this bug anyone can change a user PIN without having the PIN or PUK or the superusers PIN or PUK. However it can not be used to figure out the PIN. If the PIN on your card is still the same you always had, there's a reasonable chance that this vulnerability has not been exploited.

This vulnerability affects only smart cards and USB crypto tokens based on Siemens CardOS M4, and within that group only those that were initialised with OpenSC. Users of other smart cards and USB crypto tokens, or cards that have been initialised with some software other than OpenSC, are not affected.

After upgrading the package, running pkcs15-tool -T will show you whether the card is fine or vulnerable. If the card is vulnerable, you need to update the security setting using: pkcs15-tool -T -U.

For the stable distribution (etch), this problem has been fixed in version 0.11.1-2etch2.

For the unstable distribution (sid), this problem has been fixed in version 0.11.4-5.

We recommend that you upgrade your opensc package and check your card(s) with the command described above.");

  script_tag(name:"affected", value:"'opensc' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopensc2", ver:"0.11.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopensc2-dbg", ver:"0.11.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopensc2-dev", ver:"0.11.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-opensc", ver:"0.11.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.11.1-2etch2", rls:"DEB4"))) {
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
