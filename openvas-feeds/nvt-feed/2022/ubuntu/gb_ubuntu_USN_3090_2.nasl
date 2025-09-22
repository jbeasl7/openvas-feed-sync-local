# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2016.3090.2");
  script_cve_id("CVE-2014-9601");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-3090-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3090-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3090-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1628351");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pillow' package(s) announced via the USN-3090-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3090-1 fixed vulnerabilities in Pillow. The patch to fix CVE-2014-9601
caused a regression which resulted in failures when processing certain
png images. This update temporarily reverts the security fix for CVE-2014-9601
pending further investigation.

We apologize for the inconvenience.

Original advisory details:

It was discovered that a flaw in processing a compressed text chunk in
a PNG image could cause the image to have a large size when decompressed,
potentially leading to a denial of service. (CVE-2014-9601)

Andrew Drake discovered that Pillow incorrectly validated input. A remote
attacker could use this to cause Pillow to crash, resulting in a denial
of service. (CVE-2014-3589)

Eric Soroos discovered that Pillow incorrectly handled certain malformed
FLI, Tiff, and PhotoCD files. A remote attacker could use this issue to
cause Pillow to crash, resulting in a denial of service.
(CVE-2016-0740, CVE-2016-0775, CVE-2016-2533)");

  script_tag(name:"affected", value:"'pillow' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-imaging", ver:"2.3.0-1ubuntu3.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pil", ver:"2.3.0-1ubuntu3.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-imaging", ver:"2.3.0-1ubuntu3.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"2.3.0-1ubuntu3.3", rls:"UBUNTU14.04 LTS"))) {
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
