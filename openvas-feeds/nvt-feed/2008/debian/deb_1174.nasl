# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57359");
  script_cve_id("CVE-2006-4339");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1174-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1174-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1174");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl096' package(s) announced via the DSA-1174-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Bleichenbacher discovered a flaw in the OpenSSL cryptographic package that could allow an attacker to generate a forged signature that OpenSSL will accept as valid.

For the stable distribution (sarge) this problem has been fixed in version 0.9.6m-1sarge2.

This package exists only for compatibility with older software, and is not present in the unstable or testing branches of Debian.

We recommend that you upgrade your openssl packages. Note that services linking against the openssl shared libraries will need to be restarted. Common examples of such services include most Mail Transport Agents, SSH servers, and web servers.");

  script_tag(name:"affected", value:"'openssl096' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.6", ver:"0.9.6m-1sarge2", rls:"DEB3.1"))) {
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
