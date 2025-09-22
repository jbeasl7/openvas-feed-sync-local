# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840166");
  script_cve_id("CVE-2006-6332");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-404-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.10");

  script_xref(name:"Advisory-ID", value:"USN-404-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-404-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-restricted-modules-2.6.17' package(s) announced via the USN-404-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Laurent Butti, Jerome Razniewski, and Julien Tinnes discovered that the
MadWifi wireless driver did not correctly check packet contents when
receiving scan replies. A remote attacker could send a specially
crafted packet and execute arbitrary code with root privileges.");

  script_tag(name:"affected", value:"'linux-restricted-modules-2.6.17' package(s) on Ubuntu 6.10.");

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

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-10-386", ver:"2.6.17.7-10.1", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-10-generic", ver:"2.6.17.7-10.1", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-10-powerpc", ver:"2.6.17.7-10.1", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-10-powerpc-smp", ver:"2.6.17.7-10.1", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-10-powerpc64-smp", ver:"2.6.17.7-10.1", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-10-sparc64", ver:"2.6.17.7-10.1", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-restricted-modules-2.6.17-10-sparc64-smp", ver:"2.6.17.7-10.1", rls:"UBUNTU6.10"))) {
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
