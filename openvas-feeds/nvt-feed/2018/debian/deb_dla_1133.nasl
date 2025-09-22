# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891133");
  script_cve_id("CVE-2017-11704", "CVE-2017-11728", "CVE-2017-11729", "CVE-2017-11730", "CVE-2017-11731", "CVE-2017-11734");
  script_tag(name:"creation_date", value:"2018-02-06 23:00:00 +0000 (Tue, 06 Feb 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-02 18:01:30 +0000 (Wed, 02 Aug 2017)");

  script_name("Debian: Security Advisory (DLA-1133-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1133-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/DLA-1133-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ming' package(s) announced via the DLA-1133-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Ming:

CVE-2017-11704

Heap-based buffer over-read in the function decompileIF in util/decompile.c in Ming <= 0.4.8, which allows attackers to cause a denial of service via a crafted file.

CVE-2017-11728

Heap-based buffer over-read in the function OpCode (called from decompileSETMEMBER) in util/decompile.c in Ming <= 0.4.8, which allows attackers to cause a denial of service via a crafted file.

CVE-2017-11729

Heap-based buffer over-read in the function OpCode (called from decompileINCR_DECR line 1440) in util/decompile.c in Ming <= 0.4.8, which allows attackers to cause a denial of service via a crafted file.

CVE-2017-11730

Heap-based buffer over-read in the function OpCode (called from decompileINCR_DECR line 1474) in util/decompile.c in Ming <= 0.4.8, which allows attackers to cause a denial of service via a crafted file.

CVE-2017-11731

Invalid memory read in the function OpCode (called from isLogicalOp and decompileIF) in util/decompile.c in Ming <= 0.4.8, which allows attackers to cause a denial of service via a crafted file.

CVE-2017-11734

Heap-based buffer over-read in the function decompileCALLFUNCTION in util/decompile.c in Ming <= 0.4.8, which allows attackers to cause a denial of service via a crafted file.

For Debian 7 Wheezy, these problems have been fixed in version 1:0.4.4-1.1+deb7u4.

We recommend that you upgrade your ming packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ming' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libming-dev", ver:"1:0.4.4-1.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libming-util", ver:"1:0.4.4-1.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libming1", ver:"1:0.4.4-1.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswf-perl", ver:"1:0.4.4-1.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ming-fonts-dejavu", ver:"1:0.4.4-1.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ming-fonts-opensymbol", ver:"1:0.4.4-1.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-ming", ver:"1:0.4.4-1.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-ming", ver:"1:0.4.4-1.1+deb7u4", rls:"DEB7"))) {
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
