# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702783");
  script_cve_id("CVE-2011-5036", "CVE-2013-0183", "CVE-2013-0184", "CVE-2013-0263");
  script_tag(name:"creation_date", value:"2013-10-20 22:00:00 +0000 (Sun, 20 Oct 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2783-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2783-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2783-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2783");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'librack-ruby' package(s) announced via the DSA-2783-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Rack, a modular Ruby webserver interface. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2011-5036

Rack computes hash values for form parameters without restricting the ability to trigger hash collisions predictably, which allows remote attackers to cause a denial of service (CPU consumption) by sending many crafted parameters.

CVE-2013-0183

A remote attacker could cause a denial of service (memory consumption and out-of-memory error) via a long string in a Multipart HTTP packet.

CVE-2013-0184

A vulnerability in Rack::Auth::AbstractRequest allows remote attackers to cause a denial of service via unknown vectors.

CVE-2013-0263

Rack::Session::Cookie allows remote attackers to guess the session cookie, gain privileges, and execute arbitrary code via a timing attack involving an HMAC comparison function that does not run in constant time.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.1.0-4+squeeze1.

The stable, testing and unstable distributions do not contain the librack-ruby package. They have already been addressed in version 1.4.1-2.1 of the ruby-rack package.

We recommend that you upgrade your librack-ruby packages.");

  script_tag(name:"affected", value:"'librack-ruby' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"librack-ruby", ver:"1.1.0-4+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librack-ruby1.8", ver:"1.1.0-4+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"librack-ruby1.9.1", ver:"1.1.0-4+squeeze1", rls:"DEB6"))) {
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
