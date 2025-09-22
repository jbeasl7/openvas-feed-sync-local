# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843160");
  script_cve_id("CVE-2017-8900");
  script_tag(name:"creation_date", value:"2017-05-12 04:50:42 +0000 (Fri, 12 May 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-26 14:46:08 +0000 (Fri, 26 May 2017)");

  script_name("Ubuntu: Security Advisory (USN-3285-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.10|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3285-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3285-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1663157");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lightdm' package(s) announced via the USN-3285-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tyler Hicks discovered that LightDM did not confine the user session for guest
users. An attacker with physical access could use this issue to access files
and other resources that they should not be able to access. In the default
installation, this includes files in the home directories of other users on the
system. This update fixes the issue by disabling the guest session. It may be
re-enabled in a future update. Please see the bug referenced below for
instructions on how to manually re-enable the guest session.");

  script_tag(name:"affected", value:"'lightdm' package(s) on Ubuntu 16.10, Ubuntu 17.04.");

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

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"lightdm", ver:"1.19.5-0ubuntu1.2", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"lightdm", ver:"1.22.0-0ubuntu2.1", rls:"UBUNTU17.04"))) {
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
