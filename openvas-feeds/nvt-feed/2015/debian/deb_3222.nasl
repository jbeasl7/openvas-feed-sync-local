# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703222");
  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");
  script_tag(name:"creation_date", value:"2015-04-11 22:00:00 +0000 (Sat, 11 Apr 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 17:52:07 +0000 (Tue, 17 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-3222-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3222-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/DSA-3222-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3222");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chrony' package(s) announced via the DSA-3222-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Miroslav Lichvar of Red Hat discovered multiple vulnerabilities in chrony, an alternative NTP client and server:

CVE-2015-1821

Using particular address/subnet pairs when configuring access control would cause an invalid memory write. This could allow attackers to cause a denial of service (crash) or execute arbitrary code.

CVE-2015-1822

When allocating memory to save unacknowledged replies to authenticated command requests, a pointer would be left uninitialized, which could trigger an invalid memory write. This could allow attackers to cause a denial of service (crash) or execute arbitrary code.

CVE-2015-1853

When peering with other NTP hosts using authenticated symmetric association, the internal state variables would be updated before the MAC of the NTP messages was validated. This could allow a remote attacker to cause a denial of service by impeding synchronization between NTP peers.

For the stable distribution (wheezy), these problems have been fixed in version 1.24-3.1+deb7u3.

For the unstable distribution (sid), these problems have been fixed in version 1.30-2.

We recommend that you upgrade your chrony packages.");

  script_tag(name:"affected", value:"'chrony' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"chrony", ver:"1.24-3.1+deb7u3", rls:"DEB7"))) {
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
