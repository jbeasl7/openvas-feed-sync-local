# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57585");
  script_cve_id("CVE-2006-4924", "CVE-2006-5051");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-08-04T05:47:09+0000");
  script_tag(name:"last_modification", value:"2025-08-04 05:47:09 +0000 (Mon, 04 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:36:44 +0000 (Fri, 02 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1212-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1212-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1212-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1212");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DSA-1212-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two denial of service problems have been found in the OpenSSH server. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2006-4924

The sshd support for ssh protocol version 1 does not properly handle duplicate incoming blocks. This could allow a remote attacker to cause sshd to consume significant CPU resources leading to a denial of service.

CVE-2006-5051

A signal handler race condition could potentially allow a remote attacker to crash sshd and could theoretically lead to the ability to execute arbitrary code.

For the stable distribution (sarge), these problems have been fixed in version 1:3.8.1p1-8.sarge.6.

For the unstable and testing distributions, these problems have been fixed in version 1:4.3p2-4.

We recommend that you upgrade your openssh package.");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client-udeb", ver:"1:3.8.1p1-8.sarge.6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server-udeb", ver:"1:3.8.1p1-8.sarge.6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh", ver:"1:3.8.1p1-8.sarge.6", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:3.8.1p1-8.sarge.6", rls:"DEB3.1"))) {
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
