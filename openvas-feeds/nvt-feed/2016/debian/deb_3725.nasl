# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703725");
  script_cve_id("CVE-2014-9911", "CVE-2015-2632", "CVE-2015-4844", "CVE-2016-0494", "CVE-2016-6293", "CVE-2016-7415");
  script_tag(name:"creation_date", value:"2016-11-26 23:00:00 +0000 (Sat, 26 Nov 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-20 01:58:50 +0000 (Tue, 20 Sep 2016)");

  script_name("Debian: Security Advisory (DSA-3725-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3725-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3725-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3725");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icu' package(s) announced via the DSA-3725-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the International Components for Unicode (ICU) library.

CVE-2014-9911

Michele Spagnuolo discovered a buffer overflow vulnerability which might allow remote attackers to cause a denial of service or possibly execute arbitrary code via crafted text.

CVE-2015-2632

An integer overflow vulnerability might lead into a denial of service or disclosure of portion of application memory if an attacker has control on the input file.

CVE-2015-4844

Buffer overflow vulnerabilities might allow an attacker with control on the font file to perform a denial of service or, possibly, execute arbitrary code.

CVE-2016-0494

Integer signedness issues were introduced as part of the CVE-2015-4844 fix.

CVE-2016-6293

A buffer overflow might allow an attacker to perform a denial of service or disclosure of portion of application memory.

CVE-2016-7415

A stack-based buffer overflow might allow an attacker with control on the locale string to perform a denial of service and, possibly, execute arbitrary code.

For the stable distribution (jessie), these problems have been fixed in version 52.1-8+deb8u4.

For the unstable distribution (sid), these problems have been fixed in version 57.1-5.

We recommend that you upgrade your icu packages.");

  script_tag(name:"affected", value:"'icu' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"icu-devtools", ver:"52.1-8+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icu-doc", ver:"52.1-8+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libicu-dev", ver:"52.1-8+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libicu52", ver:"52.1-8+deb8u4", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libicu52-dbg", ver:"52.1-8+deb8u4", rls:"DEB8"))) {
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
