# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891565");
  script_cve_id("CVE-2018-14651", "CVE-2018-14652", "CVE-2018-14653", "CVE-2018-14659", "CVE-2018-14661");
  script_tag(name:"creation_date", value:"2018-11-05 23:00:00 +0000 (Mon, 05 Nov 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-31 19:16:53 +0000 (Mon, 31 Dec 2018)");

  script_name("Debian: Security Advisory (DLA-1565-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1565-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/DLA-1565-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'glusterfs' package(s) announced via the DLA-1565-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities were discovered in GlusterFS, a clustered file system. Buffer overflows and path traversal issues may lead to information disclosure, denial-of-service or the execution of arbitrary code.

CVE-2018-14651

It was found that the fix for CVE-2018-10927, CVE-2018-10928, CVE-2018-10929, CVE-2018-10930, and CVE-2018-10926 was incomplete. A remote, authenticated attacker could use one of these flaws to execute arbitrary code, create arbitrary files, or cause denial of service on glusterfs server nodes via symlinks to relative paths.

CVE-2018-14652

The Gluster file system is vulnerable to a buffer overflow in the 'features/index' translator via the code handling the GF_XATTR_CLRLK_CMD xattr in the pl_getxattr function. A remote authenticated attacker could exploit this on a mounted volume to cause a denial of service.

CVE-2018-14653

The Gluster file system is vulnerable to a heap-based buffer overflow in the __server_getspec function via the gf_getspec_req RPC message. A remote authenticated attacker could exploit this to cause a denial of service or other potential unspecified impact.

CVE-2018-14659

The Gluster file system is vulnerable to a denial of service attack via use of the GF_XATTR_IOSTATS_DUMP_KEY xattr. A remote, authenticated attacker could exploit this by mounting a Gluster volume and repeatedly calling 'setxattr(2)' to trigger a state dump and create an arbitrary number of files in the server's runtime directory.

CVE-2018-14661

It was found that usage of snprintf function in feature/locks translator of glusterfs server was vulnerable to a format string attack. A remote, authenticated attacker could use this flaw to cause remote denial of service.

For Debian 8 Jessie, these problems have been fixed in version 3.5.2-2+deb8u5.

We recommend that you upgrade your glusterfs packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'glusterfs' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-client", ver:"3.5.2-2+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-common", ver:"3.5.2-2+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-dbg", ver:"3.5.2-2+deb8u5", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"glusterfs-server", ver:"3.5.2-2+deb8u5", rls:"DEB8"))) {
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
