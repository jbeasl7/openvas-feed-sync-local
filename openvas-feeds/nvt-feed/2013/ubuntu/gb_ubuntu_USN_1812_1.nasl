# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841412");
  script_cve_id("CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0913", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1848", "CVE-2013-1860", "CVE-2013-2206", "CVE-2013-2634", "CVE-2013-2635");
  script_tag(name:"creation_date", value:"2013-06-14 07:23:04 +0000 (Fri, 14 Jun 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1812-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1812-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1812-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-quantal' package(s) announced via the USN-1812-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathias Krause discovered an information leak in the Linux kernel's UDF
file system implementation. A local user could exploit this flaw to examine
some of the kernel's heap memory. (CVE-2012-6548)

Mathias Krause discovered an information leak in the Linux kernel's ISO
9660 CDROM file system driver. A local user could exploit this flaw to
examine some of the kernel's heap memory. (CVE-2012-6549)

An integer overflow was discovered in the Direct Rendering Manager (DRM)
subsystem for the i915 video driver in the Linux kernel. A local user could
exploit this flaw to cause a denial of service (crash) or potentially
escalate privileges. (CVE-2013-0913)

Andrew Honig discovered a flaw in guest OS time updates in the Linux
kernel's KVM (Kernel-based Virtual Machine). A privileged guest user could
exploit this flaw to cause a denial of service (crash host system) or
potential escalate privilege to the host kernel level. (CVE-2013-1796)

Andrew Honig discovered a use after free error in guest OS time updates in
the Linux kernel's KVM (Kernel-based Virtual Machine). A privileged guest
user could exploit this flaw to escalate privilege to the host kernel
level. (CVE-2013-1797)

Andrew Honig reported a flaw in the way KVM (Kernel-based Virtual Machine)
emulated the IOAPIC. A privileged guest user could exploit this flaw to
read host memory or cause a denial of service (crash the host).
(CVE-2013-1798)

A format-string bug was discovered in the Linux kernel's ext3 filesystem
driver. A local user could exploit this flaw to possibly escalate
privileges on the system. (CVE-2013-1848)

A buffer overflow was discovered in the Linux Kernel's USB subsystem for
devices reporting the cdc-wdm class. A specially crafted USB device when
plugged-in could cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2013-1860)

A flaw was discovered in the SCTP (stream control transfer protocol)
network protocol's handling of duplicate cookies in the Linux kernel. A
remote attacker could exploit this flaw to cause a denial of service
(system crash) on another remote user querying the SCTP connection.
(CVE-2013-2206)

An information leak in the Linux kernel's dcb netlink interface was
discovered. A local user could obtain sensitive information by examining
kernel stack memory. (CVE-2013-2634)

A kernel stack information leak was discovered in the RTNETLINK component
of the Linux kernel. A local user could read sensitive information from the
kernel stack. (CVE-2013-2635)");

  script_tag(name:"affected", value:"'linux-lts-quantal' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.5.0-28-generic", ver:"3.5.0-28.48~precise1", rls:"UBUNTU12.04 LTS"))) {
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
