# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70560");
  script_cve_id("CVE-2011-4130");
  script_tag(name:"creation_date", value:"2012-02-11 07:30:05 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2346-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2346-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2346-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2346");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd-dfsg' package(s) announced via the DSA-2346-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in ProFTPD, an FTP server:

(No CVE id) ProFTPD incorrectly uses data from an unencrypted input buffer after encryption has been enabled with STARTTLS, an issue similar to CVE-2011-0411.

CVE-2011-4130

ProFTPD uses a response pool after freeing it under exceptional conditions, possibly leading to remote code execution. (The version in lenny is not affected by this problem.)

For the oldstable distribution (lenny), this problem has been fixed in version 1.3.1-17lenny9.

For the stable distribution (squeeze), this problem has been fixed in version 1.3.3a-6squeeze4.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 1.3.4~rc3-2.

We recommend that you upgrade your proftpd-dfsg packages.");

  script_tag(name:"affected", value:"'proftpd-dfsg' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"proftpd", ver:"1.3.1-17lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-basic", ver:"1.3.1-17lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-doc", ver:"1.3.1-17lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-ldap", ver:"1.3.1-17lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-mysql", ver:"1.3.1-17lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"proftpd-mod-pgsql", ver:"1.3.1-17lenny9", rls:"DEB5"))) {
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
