# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63730");
  script_cve_id("CVE-2009-1073");
  script_tag(name:"creation_date", value:"2009-04-06 18:58:11 +0000 (Mon, 06 Apr 2009)");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 21:31:04 +0000 (Thu, 15 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1758-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1758-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1758-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1758");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss-ldapd' package(s) announced via the DSA-1758-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Leigh James discovered that nss-ldapd, an NSS module for using LDAP as a naming service, by default creates the configuration file /etc/nss-ldapd.conf world-readable which could leak the configured LDAP password if one is used for connecting to the LDAP server.

The old stable distribution (etch) doesn't contain nss-ldapd.

For the stable distribution (lenny) this problem has been fixed in version 0.6.7.1.

For the unstable distribution (sid) this problem has been fixed in version 0.6.8.

We recommend that you upgrade your nss-ldapd package.");

  script_tag(name:"affected", value:"'nss-ldapd' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss-ldapd", ver:"0.6.7.1", rls:"DEB5"))) {
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
