# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120399");
  script_cve_id("CVE-2011-1162", "CVE-2011-1577", "CVE-2011-2494", "CVE-2011-2699", "CVE-2011-2905", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3353", "CVE-2011-3359", "CVE-2011-3363", "CVE-2011-3593", "CVE-2011-4110", "CVE-2011-4132", "CVE-2011-4326");
  script_tag(name:"creation_date", value:"2015-09-08 09:24:42 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 10:59:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2011-26)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2011-26");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2011-26.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ALAS-2011-26 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IPv6 fragment identification value generation could allow a remote attacker to disrupt a target system's networking, preventing legitimate users from accessing its services. (CVE-2011-2699, Important)

A signedness issue was found in the Linux kernel's CIFS (Common Internet File System) implementation. A malicious CIFS server could send a specially-crafted response to a directory read request that would result in a denial of service or privilege escalation on a system that has a CIFS share mounted. (CVE-2011-3191, Important)

A flaw was found in the way the Linux kernel handled fragmented IPv6 UDP datagrams over the bridge with UDP Fragmentation Offload (UFO) functionality on. A remote attacker could use this flaw to cause a denial of service. (CVE-2011-4326, Important)

The way IPv4 and IPv6 protocol sequence numbers and fragment IDs were generated could allow a man-in-the-middle attacker to inject packets and possibly hijack connections. Protocol sequence numbers and fragment IDs are now more random. (CVE-2011-3188, Moderate)

A buffer overflow flaw was found in the Linux kernel's FUSE (Filesystem in Userspace) implementation. A local user in the fuse group who has access to mount a FUSE file system could use this flaw to cause a denial of service. (CVE-2011-3353, Moderate)

A flaw was found in the b43 driver in the Linux kernel. If a system had an active wireless interface that uses the b43 driver, an attacker able to send a specially-crafted frame to that interface could cause a denial of service. (CVE-2011-3359, Moderate)

A flaw was found in the way CIFS shares with DFS referrals at their root were handled. An attacker on the local network who is able to deploy a malicious CIFS server could create a CIFS network share that, when mounted, would cause the client system to crash. (CVE-2011-3363, Moderate)

A flaw was found in the way the Linux kernel handled VLAN 0 frames with the priority tag set. When using certain network drivers, an attacker on the local network could use this flaw to cause a denial of service. (CVE-2011-3593, Moderate)

A flaw in the way memory containing security-related data was handled in tpm_read() could allow a local, unprivileged user to read the results of a previously run TPM command. (CVE-2011-1162, Low)

A heap overflow flaw was found in the Linux kernel's EFI GUID Partition Table (GPT) implementation. A local attacker could use this flaw to cause a denial of service by mounting a disk that contains specially-crafted partition tables. (CVE-2011-1577, Low)

The I/O statistics from the taskstats subsystem could be read without any restrictions. A local, unprivileged user could use this flaw to gather confidential information, such as the length of a password used in a process. (CVE-2011-2494, Low)

It was found that the perf tool, a part of the Linux kernel's Performance Events implementation, could load its configuration file from the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Amazon Linux.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.35.14~106.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.35.14~106.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.35.14~106.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.35.14~106.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.35.14~106.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.35.14~106.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.35.14~106.49.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.35.14~106.49.amzn1", rls:"AMAZON"))) {
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
