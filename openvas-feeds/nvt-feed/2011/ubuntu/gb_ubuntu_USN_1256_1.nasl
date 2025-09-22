# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840802");
  script_cve_id("CVE-2011-1020", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1180", "CVE-2011-1478", "CVE-2011-1479", "CVE-2011-1493", "CVE-2011-1573", "CVE-2011-1576", "CVE-2011-1577", "CVE-2011-1581", "CVE-2011-1585", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-1771", "CVE-2011-1776", "CVE-2011-1833", "CVE-2011-2182", "CVE-2011-2213", "CVE-2011-2479", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2493", "CVE-2011-2496", "CVE-2011-2497", "CVE-2011-2525", "CVE-2011-2689", "CVE-2011-2695", "CVE-2011-2699", "CVE-2011-2700", "CVE-2011-2723", "CVE-2011-2918", "CVE-2011-2928", "CVE-2011-2942", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3209", "CVE-2011-3363", "CVE-2011-3619", "CVE-2011-3637", "CVE-2011-4087", "CVE-2011-4326", "CVE-2011-4914");
  script_tag(name:"creation_date", value:"2011-11-11 04:25:49 +0000 (Fri, 11 Nov 2011)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-06-10 13:37:00 +0000 (Mon, 10 Jun 2013)");

  script_name("Ubuntu: Security Advisory (USN-1256-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1256-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1256-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-backport-natty' package(s) announced via the USN-1256-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the /proc filesystem did not correctly handle
permission changes when programs executed. A local attacker could hold open
files to examine details about programs running with higher privileges,
potentially increasing the chances of exploiting additional
vulnerabilities. (CVE-2011-1020)

Vasiliy Kulikov discovered that the Bluetooth stack did not correctly clear
memory. A local attacker could exploit this to read kernel stack memory,
leading to a loss of privacy. (CVE-2011-1078)

Vasiliy Kulikov discovered that the Bluetooth stack did not correctly check
that device name strings were NULL terminated. A local attacker could
exploit this to crash the system, leading to a denial of service, or leak
contents of kernel stack memory, leading to a loss of privacy.
(CVE-2011-1079)

Vasiliy Kulikov discovered that bridge network filtering did not check that
name fields were NULL terminated. A local attacker could exploit this to
leak contents of kernel stack memory, leading to a loss of privacy.
(CVE-2011-1080)

Johan Hovold discovered that the DCCP network stack did not correctly
handle certain packet combinations. A remote attacker could send specially
crafted network traffic that would crash the system, leading to a denial of
service. (CVE-2011-1093)

Peter Huewe discovered that the TPM device did not correctly initialize
memory. A local attacker could exploit this to read kernel heap memory
contents, leading to a loss of privacy. (CVE-2011-1160)

Dan Rosenberg discovered that the IRDA subsystem did not correctly check
certain field sizes. If a system was using IRDA, a remote attacker could
send specially crafted traffic to crash the system or gain root privileges.
(CVE-2011-1180)

Ryan Sweat discovered that the GRO code did not correctly validate memory.
In some configurations on systems using VLANs, a remote attacker could send
specially crafted traffic to crash the system, leading to a denial of
service. (CVE-2011-1478)

It was discovered that the security fix for CVE-2010-4250 introduced a
regression. A remote attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-1479)

Dan Rosenberg discovered that the X.25 Rose network stack did not correctly
handle certain fields. If a system was running with Rose enabled, a remote
attacker could send specially crafted traffic to gain root privileges.
(CVE-2011-1493)

It was discovered that the Stream Control Transmission Protocol (SCTP)
implementation incorrectly calculated lengths. If the net.sctp.addip_enable
variable was turned on, a remote attacker could send specially crafted
traffic to crash the system. (CVE-2011-1573)

Ryan Sweat discovered that the kernel incorrectly handled certain VLAN
packets. On some systems, a remote attacker could send specially crafted
traffic to crash the system, leading to a denial of service.
(CVE-2011-1576)

Timo Warns discovered that the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-lts-backport-natty' package(s) on Ubuntu 10.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-12-generic", ver:"2.6.38-12.51~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-12-generic-pae", ver:"2.6.38-12.51~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-12-server", ver:"2.6.38-12.51~lucid1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-12-virtual", ver:"2.6.38-12.51~lucid1", rls:"UBUNTU10.04 LTS"))) {
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
