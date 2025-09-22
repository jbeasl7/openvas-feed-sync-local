# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840308");
  script_cve_id("CVE-2008-1722", "CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-656-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.04|7\.10|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-656-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-656-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cupsys' package(s) announced via the USN-656-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the SGI image filter in CUPS did not perform
proper bounds checking. If a user or automated system were tricked
into opening a crafted SGI image, an attacker could cause a denial
of service. (CVE-2008-3639)

It was discovered that the texttops filter in CUPS did not properly
validate page metrics. If a user or automated system were tricked into
opening a crafted text file, an attacker could cause a denial of
service. (CVE-2008-3640)

It was discovered that the HP-GL filter in CUPS did not properly check
for invalid pen parameters. If a user or automated system were tricked
into opening a crafted HP-GL or HP-GL/2 file, a remote attacker could
cause a denial of service or execute arbitrary code with user
privileges. In Ubuntu 7.10 and 8.04 LTS, attackers would be isolated by
the AppArmor CUPS profile. (CVE-2008-3641)

NOTE: The previous update for CUPS on Ubuntu 6.06 LTS did not have the
fix for CVE-2008-1722 applied. This update includes fixes for the
problem. We apologize for the inconvenience.");

  script_tag(name:"affected", value:"'cupsys' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.2.2-0ubuntu0.6.06.11", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.2.8-0ubuntu8.6", rls:"UBUNTU7.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.3.2-1ubuntu7.8", rls:"UBUNTU7.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cupsys", ver:"1.3.7-1ubuntu3.1", rls:"UBUNTU8.04 LTS"))) {
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
