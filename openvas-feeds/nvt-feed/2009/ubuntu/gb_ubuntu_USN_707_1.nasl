# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64165");
  script_cve_id("CVE-2008-5183", "CVE-2008-5184", "CVE-2008-5286", "CVE-2008-5377");
  script_tag(name:"creation_date", value:"2009-06-05 16:04:08 +0000 (Fri, 05 Jun 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2008-11-21 17:20:00 +0000 (Fri, 21 Nov 2008)");

  script_name("Ubuntu: Security Advisory (USN-707-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.10|8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-707-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-707-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups, cupsys' package(s) announced via the USN-707-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that CUPS didn't properly handle adding a large number of RSS
subscriptions. A local user could exploit this and cause CUPS to crash, leading
to a denial of service. This issue only applied to Ubuntu 7.10, 8.04 LTS and
8.10. (CVE-2008-5183)

It was discovered that CUPS did not authenticate users when adding and
cancelling RSS subscriptions. An unprivileged local user could bypass intended
restrictions and add a large number of RSS subscriptions. This issue only
applied to Ubuntu 7.10 and 8.04 LTS. (CVE-2008-5184)

It was discovered that the PNG filter in CUPS did not properly handle certain
malformed images. If a user or automated system were tricked into opening a
crafted PNG image file, a remote attacker could cause a denial of service or
execute arbitrary code with user privileges. In Ubuntu 7.10, 8.04 LTS, and 8.10,
attackers would be isolated by the AppArmor CUPS profile. (CVE-2008-5286)

It was discovered that the example pstopdf CUPS filter created log files in an
insecure way. Local users could exploit a race condition to create or overwrite
files with the privileges of the user invoking the program. This issue only
applied to Ubuntu 6.06 LTS, 7.10, and 8.04 LTS. (CVE-2008-5377)");

  script_tag(name:"affected", value:"'cups, cupsys' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.2.2-0ubuntu0.6.06.12", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.3.2-1ubuntu7.9", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.3.7-1ubuntu3.3", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"1.3.9-2ubuntu6.1", rls:"UBUNTU8.10"))) {
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
