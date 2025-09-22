# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703750");
  script_cve_id("CVE-2016-10033");
  script_tag(name:"creation_date", value:"2017-01-05 07:49:04 +0000 (Thu, 05 Jan 2017)");
  script_version("2025-07-09T05:43:50+0000");
  script_tag(name:"last_modification", value:"2025-07-09 05:43:50 +0000 (Wed, 09 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-30 16:30:42 +0000 (Thu, 30 Sep 2021)");

  script_name("Debian: Security Advisory (DSA-3750-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3750-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3750-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3750");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libphp-phpmailer' package(s) announced via the DSA-3750-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dawid Golunski discovered that PHPMailer, a popular library to send email from PHP applications, allowed a remote attacker to execute code if they were able to provide a crafted Sender address.

Note that for this issue also CVE-2016-10045 was assigned, which is a regression in the original patch proposed for CVE-2016-10033. Because the original patch was not applied in Debian, Debian was not vulnerable to CVE-2016-10045.

For the stable distribution (jessie), this problem has been fixed in version 5.2.9+dfsg-2+deb8u2.

For the unstable distribution (sid), this problem has been fixed in version 5.2.14+dfsg-2.1.

We recommend that you upgrade your libphp-phpmailer packages.");

  script_tag(name:"affected", value:"'libphp-phpmailer' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"libphp-phpmailer", ver:"5.2.9+dfsg-2+deb8u2", rls:"DEB8"))) {
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
