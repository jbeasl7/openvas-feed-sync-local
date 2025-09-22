# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6913.2");
  script_cve_id("CVE-2022-39369");
  script_tag(name:"creation_date", value:"2024-08-01 04:08:31 +0000 (Thu, 01 Aug 2024)");
  script_version("2024-08-01T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-01 05:05:42 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-05 01:52:17 +0000 (Sat, 05 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-6913-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6913-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6913-2");
  script_xref(name:"URL", value:"https://github.com/apereo/phpCAS/blob/master/docs/Upgrading");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-cas' package(s) announced via the USN-6913-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6913-1 fixed CVE-2022-39369 for Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
This update provides the corresponding fix for Ubuntu 16.04 LTS.

Original advisory details:

Filip Hejsek discovered that phpCAS was using HTTP headers to determine
the service URL used to validate tickets. A remote attacker could
possibly use this issue to gain access to a victim's account on a
vulnerable CASified service.

This security update introduces an incompatible API change. After applying
this update, third party applications need to be modified to pass in an
additional service base URL argument when constructing the client class.

For more information please refer to the section
'Upgrading 1.5.0 -> 1.6.0' of the phpCAS upgrading document:

[link moved to references]");

  script_tag(name:"affected", value:"'php-cas' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"php-cas", ver:"1.3.3-2ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
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
