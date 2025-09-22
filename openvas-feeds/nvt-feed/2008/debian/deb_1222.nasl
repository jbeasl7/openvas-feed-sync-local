# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57686");
  script_cve_id("CVE-2006-5815", "CVE-2006-6170");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1222-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1222-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1222-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1222");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd' package(s) announced via the DSA-1222-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to technical problems yesterday's proftpd update lacked a build for the amd64 architecture, which is now available. For reference please find below the original advisory text:

Several remote vulnerabilities have been discovered in the proftpd FTP daemon, which may lead to the execution of arbitrary code or denial of service. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-5815

It was discovered that a buffer overflow in the sreplace() function may lead to denial of service and possibly the execution of arbitrary code.

CVE-2006-6170

It was discovered that a buffer overflow in the mod_tls addon module may lead to the execution of arbitrary code.

CVE-2006-6171

It was discovered that insufficient validation of FTP command buffer size limits may lead to denial of service. Due to unclear information this issue was already fixed in DSA-1218 as CVE-2006-5815.

For the stable distribution (sarge) these problems have been fixed in version 1.2.10-15sarge3.

For the unstable distribution (sid) these problems have been fixed in version 1.3.0-16 of the proftpd-dfsg package.

We recommend that you upgrade your proftpd package.");

  script_tag(name:"affected", value:"'proftpd' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"proftpd", ver:"1.2.10-15sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-common", ver:"1.2.10-15sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.2.10-15sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-ldap", ver:"1.2.10-15sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mysql", ver:"1.2.10-15sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-pgsql", ver:"1.2.10-15sarge3", rls:"DEB3.1"))) {
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
