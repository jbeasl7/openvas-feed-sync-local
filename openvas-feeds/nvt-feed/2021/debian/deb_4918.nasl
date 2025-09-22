# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704918");
  script_cve_id("CVE-2019-18978");
  script_tag(name:"creation_date", value:"2021-05-19 03:00:06 +0000 (Wed, 19 May 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-18 19:02:26 +0000 (Mon, 18 Nov 2019)");

  script_name("Debian: Security Advisory (DSA-4918-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4918-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-4918-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4918");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ruby-rack-cors");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-rack-cors' package(s) announced via the DSA-4918-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper pathname handling in ruby-rack-cors, a middleware that makes Rack-based apps CORS compatible, may result in access to private resources.

For the stable distribution (buster), this problem has been fixed in version 1.0.2-1+deb10u1.

We recommend that you upgrade your ruby-rack-cors packages.

For the detailed security status of ruby-rack-cors please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-rack-cors' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rack-cors", ver:"1.0.2-1+deb10u1", rls:"DEB10"))) {
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
