# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842701");
  script_cve_id("CVE-2014-1748", "CVE-2015-1071", "CVE-2015-1076", "CVE-2015-1081", "CVE-2015-1083", "CVE-2015-1120", "CVE-2015-1122", "CVE-2015-1127", "CVE-2015-1153", "CVE-2015-1155", "CVE-2015-3658", "CVE-2015-3659", "CVE-2015-3727", "CVE-2015-3731", "CVE-2015-3741", "CVE-2015-3743", "CVE-2015-3745", "CVE-2015-3747", "CVE-2015-3748", "CVE-2015-3749", "CVE-2015-3752", "CVE-2015-5788", "CVE-2015-5794", "CVE-2015-5801", "CVE-2015-5809", "CVE-2015-5822", "CVE-2015-5928");
  script_tag(name:"creation_date", value:"2016-03-22 05:13:01 +0000 (Tue, 22 Mar 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2937-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2937-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2937-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkitgtk' package(s) announced via the USN-2937-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A large number of security issues were discovered in the WebKitGTK+ Web and
JavaScript engines. If a user were tricked into viewing a malicious
website, a remote attacker could exploit a variety of issues related to web
browser security, including cross-site scripting attacks, denial of service
attacks, and arbitrary code execution.");

  script_tag(name:"affected", value:"'webkitgtk' package(s) on Ubuntu 14.04, Ubuntu 15.10.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-1.0-0", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-3.0-0", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-1.0-0", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-3.0-0", ver:"2.4.10-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-1.0-0", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-3.0-0", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-1.0-0", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-3.0-0", ver:"2.4.10-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
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
