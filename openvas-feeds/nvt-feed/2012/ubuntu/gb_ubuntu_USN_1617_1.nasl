# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841198");
  script_cve_id("CVE-2011-3031", "CVE-2011-3038", "CVE-2011-3042", "CVE-2011-3043", "CVE-2011-3044", "CVE-2011-3051", "CVE-2011-3053", "CVE-2011-3059", "CVE-2011-3060", "CVE-2011-3064", "CVE-2011-3067", "CVE-2011-3076", "CVE-2011-3081", "CVE-2011-3086", "CVE-2011-3090", "CVE-2012-1521", "CVE-2012-3598", "CVE-2012-3601", "CVE-2012-3604", "CVE-2012-3611", "CVE-2012-3612", "CVE-2012-3617", "CVE-2012-3625", "CVE-2012-3626", "CVE-2012-3627", "CVE-2012-3628", "CVE-2012-3645", "CVE-2012-3652", "CVE-2012-3657", "CVE-2012-3669", "CVE-2012-3670", "CVE-2012-3671", "CVE-2012-3672", "CVE-2012-3674");
  script_tag(name:"creation_date", value:"2012-10-26 04:14:32 +0000 (Fri, 26 Oct 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1617-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1617-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1617-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1058339");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit' package(s) announced via the USN-1617-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A large number of security issues were discovered in the WebKit browser and
JavaScript engines. If a user were tricked into viewing a malicious
website, a remote attacker could exploit a variety of issues related to web
browser security, including cross-site scripting attacks, denial of
service attacks, and arbitrary code execution.");

  script_tag(name:"affected", value:"'webkit' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-1.0-0", ver:"1.8.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-3.0-0", ver:"1.8.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-1.0-0", ver:"1.8.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkitgtk-3.0-0", ver:"1.8.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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
