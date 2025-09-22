# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892910");
  script_cve_id("CVE-2017-1000231", "CVE-2017-1000232", "CVE-2020-19860", "CVE-2020-19861");
  script_tag(name:"creation_date", value:"2022-02-05 02:00:10 +0000 (Sat, 05 Feb 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-29 19:34:48 +0000 (Wed, 29 Nov 2017)");

  script_name("Debian: Security Advisory (DLA-2910-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2910-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-2910-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ldns' package(s) announced via the DLA-2910-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were four issues in ldns, a library used in Domain Name System (DNS) related programs:

CVE-2020-19860

When ldns version 1.7.1 verifies a zone file, the ldns_rr_new_frm_str_internal function has a heap out of bounds read vulnerability. An attacker can leak information on the heap by constructing a zone file payload.

CVE-2020-19861

When a zone file in ldns 1.7.1 is parsed, the function ldns_nsec3_salt_data is too trusted for the length value obtained from the zone file. When the memcpy is copied, the 0xfe - ldns_rdf_size(salt_rdf) byte data can be copied, causing heap overflow information leakage.

CVE-2017-1000231

A double-free vulnerability in parse.c in ldns 1.7.0 have unspecified impact and attack vectors.

CVE-2017-1000232

A double-free vulnerability in str2host.c in ldns 1.7.0 have unspecified impact and attack vectors.

For Debian 9 Stretch, these four problems have been fixed in version 1.7.0-1+deb9u1.

We recommend that you upgrade your ldns packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ldns' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"ldnsutils", ver:"1.7.0-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldns-dev", ver:"1.7.0-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libldns2", ver:"1.7.0-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ldns", ver:"1.7.0-1+deb9u1", rls:"DEB9"))) {
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
