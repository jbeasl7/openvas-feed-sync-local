# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892705");
  script_cve_id("CVE-2021-30485", "CVE-2021-31229", "CVE-2021-31347", "CVE-2021-31348", "CVE-2021-31598");
  script_tag(name:"creation_date", value:"2021-07-09 03:00:10 +0000 (Fri, 09 Jul 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-14 14:45:48 +0000 (Fri, 14 May 2021)");

  script_name("Debian: Security Advisory (DLA-2705-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2705-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2705-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/scilab");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'scilab' package(s) announced via the DLA-2705-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been discovered in scilab, particularly in ezXML embedded library:

CVE-2021-30485

Descriptionincorrect memory handling, leading to a NULL pointer dereference in ezxml_internal_dtd()

CVE-2021-31229

Out-of-bounds write in ezxml_internal_dtd() leading to out-of-bounds write of a one byte constant

CVE-2021-31347, CVE-2021-31348 incorrect memory handling in ezxml_parse_str() leading to out-of-bounds read

CVE-2021-31598

Out-of-bounds write in ezxml_decode() leading to heap corruption

For Debian 9 stretch, these problems have been fixed in version 5.5.2-4+deb9u1.

We recommend that you upgrade your scilab packages.

For the detailed security status of scilab please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'scilab' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"scilab", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-cli", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-data", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-doc", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-doc-fr", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-doc-ja", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-doc-pt-br", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-full-bin", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-full-bin-dbg", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-include", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-minimal-bin", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-minimal-bin-dbg", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scilab-test", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
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
