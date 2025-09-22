# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2024.4004");
  script_cve_id("CVE-2021-34193", "CVE-2021-42778", "CVE-2021-42779", "CVE-2021-42780", "CVE-2021-42781", "CVE-2021-42782", "CVE-2023-2977", "CVE-2023-40660", "CVE-2023-40661", "CVE-2023-5992", "CVE-2024-1454", "CVE-2024-45615", "CVE-2024-45616", "CVE-2024-45617", "CVE-2024-45618", "CVE-2024-45619", "CVE-2024-45620", "CVE-2024-8443");
  script_tag(name:"creation_date", value:"2024-12-30 04:09:15 +0000 (Mon, 30 Dec 2024)");
  script_version("2024-12-30T08:11:52+0000");
  script_tag(name:"last_modification", value:"2024-12-30 08:11:52 +0000 (Mon, 30 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-28 17:04:48 +0000 (Mon, 28 Aug 2023)");

  script_name("Debian: Security Advisory (DLA-4004-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4004-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2024/DLA-4004-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'opensc' package(s) announced via the DLA-4004-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'opensc' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.21.0-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.21.0-1+deb11u1", rls:"DEB11"))) {
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
