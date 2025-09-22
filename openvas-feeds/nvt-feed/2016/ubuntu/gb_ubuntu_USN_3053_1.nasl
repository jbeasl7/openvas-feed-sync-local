# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842859");
  script_cve_id("CVE-2016-1237", "CVE-2016-4470", "CVE-2016-4794", "CVE-2016-5243");
  script_tag(name:"creation_date", value:"2016-08-11 03:37:57 +0000 (Thu, 11 Aug 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-24 14:19:18 +0000 (Tue, 24 May 2016)");

  script_name("Ubuntu: Security Advisory (USN-3053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3053-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3053-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-vivid' package(s) announced via the USN-3053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A missing permission check when settings ACLs was discovered in nfsd. A
local user could exploit this flaw to gain access to any file by setting an
ACL. (CVE-2016-1237)

It was discovered that the keyring implementation in the Linux kernel did
not ensure a data structure was initialized before referencing it after an
error condition occurred. A local attacker could use this to cause a denial
of service (system crash). (CVE-2016-4470)

Sasha Levin discovered that a use-after-free existed in the percpu
allocator in the Linux kernel. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code with
administrative privileges. (CVE-2016-4794)

Kangjie Lu discovered an information leak in the netlink implementation of
the Linux kernel. A local attacker could use this to obtain sensitive
information from kernel memory. (CVE-2016-5243)");

  script_tag(name:"affected", value:"'linux-lts-vivid' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-66-generic", ver:"3.19.0-66.74~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-66-generic-lpae", ver:"3.19.0-66.74~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-66-lowlatency", ver:"3.19.0-66.74~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-66-powerpc-e500mc", ver:"3.19.0-66.74~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-66-powerpc-smp", ver:"3.19.0-66.74~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-66-powerpc64-emb", ver:"3.19.0-66.74~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.19.0-66-powerpc64-smp", ver:"3.19.0-66.74~14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
