# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890994");
  script_cve_id("CVE-2017-5974", "CVE-2017-5975", "CVE-2017-5976", "CVE-2017-5978", "CVE-2017-5979", "CVE-2017-5980", "CVE-2017-5981");
  script_tag(name:"creation_date", value:"2018-01-28 23:00:00 +0000 (Sun, 28 Jan 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-01 18:42:14 +0000 (Wed, 01 Mar 2017)");

  script_name("Debian: Security Advisory (DLA-994-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-994-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/DLA-994-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zziplib' package(s) announced via the DLA-994-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-5974

Heap-based buffer overflow in the __zzip_get32 function in fetch.c in zziplib allows remote attackers to cause a denial of service (crash) via a crafted ZIP file.

CVE-2017-5975

Heap-based buffer overflow in the __zzip_get64 function in fetch.c in zziplib allows remote attackers to cause a denial of service (crash) via a crafted ZIP file.

CVE-2017-5976

Heap-based buffer overflow in the zzip_mem_entry_extra_block function in memdisk.c in zziplib allows remote attackers to cause a denial of service (crash) via a crafted ZIP file.

CVE-2017-5978

The zzip_mem_entry_new function in memdisk.c in zziplib allows remote attackers to cause a denial of service (out-of-bounds read and crash) via a crafted ZIP file.

CVE-2017-5979

The prescan_entry function in fseeko.c in zziplib allows remote attackers to cause a denial of service (NULL pointer dereference and crash) via a crafted ZIP file.

CVE-2017-5980

The zzip_mem_entry_new function in memdisk.c in zziplib allows remote attackers to cause a denial of service (NULL pointer dereference and crash) via a crafted ZIP file.

CVE-2017-5981

seeko.c in zziplib allows remote attackers to cause a denial of service (assertion failure and crash) via a crafted ZIP file.

For Debian 7 Wheezy, these problems have been fixed in version 0.13.56-1.1+deb7u1.

We recommend that you upgrade your zziplib packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'zziplib' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libzzip-0-13", ver:"0.13.56-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libzzip-dev", ver:"0.13.56-1.1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zziplib-bin", ver:"0.13.56-1.1+deb7u1", rls:"DEB7"))) {
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
