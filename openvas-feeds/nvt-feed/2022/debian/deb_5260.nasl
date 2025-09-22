# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705260");
  script_cve_id("CVE-2022-42902");
  script_tag(name:"creation_date", value:"2022-10-25 01:00:04 +0000 (Tue, 25 Oct 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-14 19:55:14 +0000 (Fri, 14 Oct 2022)");

  script_name("Debian: Security Advisory (DSA-5260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5260-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5260-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5260");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/lava");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lava' package(s) announced via the DSA-5260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Igor Ponomarev discovered that LAVA, a continuous integration system for deploying operating systems onto physical and virtual hardware for running tests, used exec() on input passed to the server component.

For the stable distribution (bullseye), this problem has been fixed in version 2020.12-5+deb11u1.

We recommend that you upgrade your lava packages.

For the detailed security status of lava please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'lava' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"lava", ver:"2020.12-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lava-common", ver:"2020.12-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lava-coordinator", ver:"2020.12-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lava-dev", ver:"2020.12-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lava-dispatcher", ver:"2020.12-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lava-dispatcher-host", ver:"2020.12-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lava-lxc-mocker", ver:"2020.12-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lava-server", ver:"2020.12-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lava-server-doc", ver:"2020.12-5+deb11u1", rls:"DEB11"))) {
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
