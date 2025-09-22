# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5698.2");
  script_cve_id("CVE-2022-32166");
  script_tag(name:"creation_date", value:"2022-10-26 04:31:54 +0000 (Wed, 26 Oct 2022)");
  script_version("2023-11-08T05:05:52+0000");
  script_tag(name:"last_modification", value:"2023-11-08 05:05:52 +0000 (Wed, 08 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5698-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5698-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5698-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvswitch' package(s) announced via the USN-5698-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5698-1 fixed a vulnerability in Open. This update provides
the corresponding update for Ubuntu 16.04 ESM.

Original advisory details:

 It was discovered that Open vSwitch incorrectly handled comparison of
 certain minimasks. A remote attacker could use this issue to cause Open
 vSwitch to crash, resulting in a denial of service, or possibly execute
 arbitrary code.");

  script_tag(name:"affected", value:"'openvswitch' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-common", ver:"2.5.9-0ubuntu0.16.04.3+esm1", rls:"UBUNTU16.04 LTS"))) {
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
