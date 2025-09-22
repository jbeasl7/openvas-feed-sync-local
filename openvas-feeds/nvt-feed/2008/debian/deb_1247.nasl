# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57788");
  script_cve_id("CVE-2006-5989");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1247-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1247-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1247-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1247");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libapache-mod-auth-kerb' package(s) announced via the DSA-1247-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An off-by-one error leading to a heap-based buffer overflow has been identified in libapache-mod-auth-kerb, an Apache module for Kerberos authentication. The error could allow an attacker to trigger an application crash or potentially execute arbitrary code by sending a specially crafted kerberos message.

For the stable distribution (sarge), this problem has been fixed in version 4.996-5.0-rc6-1sarge1.

For the unstable distribution (sid) and the forthcoming stable distribution (etch), this problem has been fixed in version 5.3-1.

We recommend that you upgrade your libapache-mod-auth-kerb package.");

  script_tag(name:"affected", value:"'libapache-mod-auth-kerb' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache-mod-auth-kerb", ver:"4.996-5.0-rc6-1sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-auth-kerb", ver:"4.996-5.0-rc6-1sarge1", rls:"DEB3.1"))) {
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
