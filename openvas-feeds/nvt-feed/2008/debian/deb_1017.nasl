# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56469");
  script_cve_id("CVE-2004-1017", "CVE-2005-0124", "CVE-2005-0449", "CVE-2005-2457", "CVE-2005-2490", "CVE-2005-2555", "CVE-2005-2709", "CVE-2005-2800", "CVE-2005-2973", "CVE-2005-3044", "CVE-2005-3053", "CVE-2005-3055", "CVE-2005-3180", "CVE-2005-3181", "CVE-2005-3257", "CVE-2005-3356", "CVE-2005-3358", "CVE-2005-3783", "CVE-2005-3784", "CVE-2005-3806", "CVE-2005-3847", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4605", "CVE-2005-4618", "CVE-2006-0095", "CVE-2006-0096", "CVE-2006-0482", "CVE-2006-1066");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 20:22:44 +0000 (Thu, 15 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-1017-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1017-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1017-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1017");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-source-2.6.8' package(s) announced via the DSA-1017-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2004-1017

Multiple overflows exist in the io_edgeport driver which might be usable as a denial of service attack vector.

CVE-2005-0124

Bryan Fulton reported a bounds checking bug in the coda_pioctl function which may allow local users to execute arbitrary code or trigger a denial of service attack.

CVE-2005-0449

An error in the skb_checksum_help() function from the netfilter framework has been discovered that allows the bypass of packet filter rules or a denial of service attack.

CVE-2005-2457

Tim Yamin discovered that insufficient input validation in the zisofs driver for compressed ISO file systems allows a denial of service attack through maliciously crafted ISO images.

CVE-2005-2490

A buffer overflow in the sendmsg() function allows local users to execute arbitrary code.

CVE-2005-2555

Herbert Xu discovered that the setsockopt() function was not restricted to users/processes with the CAP_NET_ADMIN capability. This allows attackers to manipulate IPSEC policies or initiate a denial of service attack.

CVE-2005-2709

Al Viro discovered a race condition in the /proc handling of network devices. A (local) attacker could exploit the stale reference after interface shutdown to cause a denial of service or possibly execute code in kernel mode.

CVE-2005-2800

Jan Blunck discovered that repeated failed reads of /proc/scsi/sg/devices leak memory, which allows a denial of service attack.

CVE-2005-2973

Tetsuo Handa discovered that the udp_v6_get_port() function from the IPv6 code can be forced into an endless loop, which allows a denial of service attack.

CVE-2005-3044

Vasiliy Averin discovered that the reference counters from sockfd_put() and fput() can be forced into overlapping, which allows a denial of service attack through a null pointer dereference.

CVE-2005-3053

Eric Dumazet discovered that the set_mempolicy() system call accepts a negative value for its first argument, which triggers a BUG() assert. This allows a denial of service attack.

CVE-2005-3055

Harald Welte discovered that if a process issues a USB Request Block (URB) to a device and terminates before the URB completes, a stale pointer would be dereferenced. This could be used to trigger a denial of service attack.

CVE-2005-3180

Pavel Roskin discovered that the driver for Orinoco wireless cards clears its buffers insufficiently. This could leak sensitive information into user space.

CVE-2005-3181

Robert Derr discovered that the audit subsystem uses an incorrect function to free memory, which allows a denial of service attack.

CVE-2005-3257

Rudolf Polzer discovered that the kernel improperly restricts access to the KDSKBSENT ioctl, which can possibly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-source-2.6.8' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.6.8", ver:"2.6.8-16sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-debian-2.6.8", ver:"2.6.8-16sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.6.8", ver:"2.6.8-16sarge2", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-tree-2.6.8", ver:"2.6.8-16sarge2", rls:"DEB3.1"))) {
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
