# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703120");
  script_cve_id("CVE-2013-1811", "CVE-2013-1934", "CVE-2013-4460", "CVE-2014-6316", "CVE-2014-6387", "CVE-2014-7146", "CVE-2014-8553", "CVE-2014-8554", "CVE-2014-8598", "CVE-2014-8986", "CVE-2014-8988", "CVE-2014-9089", "CVE-2014-9117", "CVE-2014-9269", "CVE-2014-9270", "CVE-2014-9271", "CVE-2014-9272", "CVE-2014-9280", "CVE-2014-9281", "CVE-2014-9388", "CVE-2014-9506");
  script_tag(name:"creation_date", value:"2015-01-05 23:00:00 +0000 (Mon, 05 Jan 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-01-12 15:58:48 +0000 (Mon, 12 Jan 2015)");

  script_name("Debian: Security Advisory (DSA-3120-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3120-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3120-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3120");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mantis' package(s) announced via the DSA-3120-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Mantis bug tracking system, which may result in phishing, information disclosure, CAPTCHA bypass, SQL injection, cross-site scripting or the execution of arbitrary PHP code.

For the stable distribution (wheezy), these problems have been fixed in version 1.2.18-1.

We recommend that you upgrade your mantis packages.");

  script_tag(name:"affected", value:"'mantis' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mantis", ver:"1.2.18-1", rls:"DEB7"))) {
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
