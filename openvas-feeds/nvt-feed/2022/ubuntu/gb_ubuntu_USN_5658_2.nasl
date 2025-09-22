# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5658.2");
  script_cve_id("CVE-2022-2928", "CVE-2022-2929");
  script_tag(name:"creation_date", value:"2022-11-08 04:25:03 +0000 (Tue, 08 Nov 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-13 13:33:13 +0000 (Thu, 13 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5658-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5658-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5658-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'isc-dhcp' package(s) announced via the USN-5658-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5658-1 fixed vulnerabilities in DHCP. This update provides
the corresponding updates for Ubuntu 16.04 ESM.

Original advisory details:

 It was discovered that DHCP incorrectly handled option reference counting.
 A remote attacker could possibly use this issue to cause DHCP servers to
 crash, resulting in a denial of service. (CVE-2022-2928)

 It was discovered that DHCP incorrectly handled certain memory operations.
 A remote attacker could possibly use this issue to cause DHCP clients and
 servers to consume resources, leading to a denial of service.
 (CVE-2022-2929)");

  script_tag(name:"affected", value:"'isc-dhcp' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.3.3-5ubuntu12.10+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.3.3-5ubuntu12.10+esm2", rls:"UBUNTU16.04 LTS"))) {
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
