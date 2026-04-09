# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8153.1");
  script_cve_id("CVE-2015-8034", "CVE-2016-3176");
  script_tag(name:"creation_date", value:"2026-04-08 04:50:57 +0000 (Wed, 08 Apr 2026)");
  script_version("2026-04-08T06:10:32+0000");
  script_tag(name:"last_modification", value:"2026-04-08 06:10:32 +0000 (Wed, 08 Apr 2026)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-07 18:41:58 +0000 (Tue, 07 Feb 2017)");

  script_name("Ubuntu: Security Advisory (USN-8153-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-8153-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8153-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the USN-8153-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zach Malone discovered that Salt did not properly handle permissions to cache
data. A local attacker could possibly use this issue to obtain sensitive
information. (CVE-2015-8034)
Dylan Frese discovered that Salt incorrectly allowed users to specify PAM
service. An attacker could possibly use this issue to bypass authentication.
(CVE-2016-3176)");

  script_tag(name:"affected", value:"'salt' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"0.17.5+ds-1ubuntu0.1~esm5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"0.17.5+ds-1ubuntu0.1~esm5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"0.17.5+ds-1ubuntu0.1~esm5", rls:"UBUNTU14.04 LTS"))) {
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
