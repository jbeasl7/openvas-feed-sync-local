# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6201.1");
  script_cve_id("CVE-2023-3482", "CVE-2023-37201", "CVE-2023-37202", "CVE-2023-37203", "CVE-2023-37204", "CVE-2023-37205", "CVE-2023-37206", "CVE-2023-37207", "CVE-2023-37208", "CVE-2023-37209", "CVE-2023-37210", "CVE-2023-37211", "CVE-2023-37212");
  script_tag(name:"creation_date", value:"2023-07-06 04:09:38 +0000 (Thu, 06 Jul 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-11 14:28:45 +0000 (Tue, 11 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6201-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6201-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6201-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-6201-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked into opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, obtain sensitive
information across domains, or execute arbitrary code. (CVE-2023-37201,
CVE-2023-37202, CVE-2023-37205, CVE-2023-37207, CVE-2023-37209,
CVE-2023-37210, CVE-2023-37211, CVE-2023-37212)

Martin Hostettler discovered that Firefox did not properly block storage of
all cookies when configured. An attacker could potentially exploits this
issue to store tracking data without permission in localstorage.
(CVE-2023-3482)

Paul Nickerson discovered that Firefox did have insufficient validation in
the Drag and Drop API. If a user were tricked into creating a shortcut to
local system files, an attacker could execute arbitrary code.
(CVE-2023-37203)

Irvan Kurniawan discovered that Firefox did not properly manage fullscreen
notifications using an option element having an expensive computational
function. An attacker could potentially exploit this issue to perform
spoofing attacks. (CVE-2023-37204)

Ameen Basha M K discovered that Firefox did not properly validate symlinks
in the FileSystem API. If a user were tricked into uploading a symlinked
file to a malicious website, an attacker could obtain sensitive information.
(CVE-2023-37206)

Puf discovered that Firefox did not properly provide warning when opening
Diagcab files. If a user were tricked into opening a malicicous Diagcab
file, an attacker could execute arbitrary code. (CVE-2023-37208)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"115.0+build2-0ubuntu0.20.04.3", rls:"UBUNTU20.04 LTS"))) {
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
