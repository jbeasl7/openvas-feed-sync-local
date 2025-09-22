# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843427");
  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_tag(name:"creation_date", value:"2018-01-23 06:38:18 +0000 (Tue, 23 Jan 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 20:47:46 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-3541-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3541-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3541-2");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SpectreAndMeltdown");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-gcp, linux-hwe, linux-oem' package(s) announced via the USN-3541-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3541-1 addressed vulnerabilities in the Linux kernel for Ubuntu
17.10. This update provides the corresponding updates for the
Linux Hardware Enablement (HWE) kernel from Ubuntu 17.10 for Ubuntu
16.04 LTS.

Jann Horn discovered that microprocessors utilizing speculative
execution and branch prediction may allow unauthorized memory
reads via sidechannel attacks. This flaw is known as Spectre. A
local attacker could use this to expose sensitive information,
including kernel memory. This update provides mitigations for the
i386 (CVE-2017-5753 only), amd64, ppc64el, and s390x architectures.
(CVE-2017-5715, CVE-2017-5753)

USN-3523-2 mitigated CVE-2017-5754 (Meltdown) for the amd64
architecture in the Linux Hardware Enablement (HWE) kernel from Ubuntu
17.10 for Ubuntu 16.04 LTS. This update provides the corresponding
mitigations for the ppc64el architecture. Original advisory details:

 Jann Horn discovered that microprocessors utilizing speculative
 execution and indirect branch prediction may allow unauthorized memory
 reads via sidechannel attacks. This flaw is known as Meltdown. A local
 attacker could use this to expose sensitive information, including
 kernel memory. (CVE-2017-5754)");

  script_tag(name:"affected", value:"'linux-azure, linux-gcp, linux-hwe, linux-oem' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-1006-azure", ver:"4.13.0-1006.8", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-1007-gcp", ver:"4.13.0-1007.10", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-1017-oem", ver:"4.13.0-1017.18", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-31-generic", ver:"4.13.0-31.34~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.13.0-31-lowlatency", ver:"4.13.0-31.34~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.13.0.1006.7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.13.0.1007.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.13.0.31.51", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.13.0.1007.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.13.0.31.51", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.13.0.1017.21", rls:"UBUNTU16.04 LTS"))) {
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
