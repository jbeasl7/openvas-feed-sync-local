# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122291");
  script_cve_id("CVE-2010-2955", "CVE-2010-2962", "CVE-2010-3079", "CVE-2010-3084", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3698", "CVE-2010-3705");
  script_tag(name:"creation_date", value:"2015-10-06 11:16:07 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 20:30:00 +0000 (Thu, 13 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2010-2011)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-2011");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-2011.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '' package(s) announced via the ELSA-2010-2011 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Following Security fixes are included in this unbreakable enterprise kernel errata:

CVE-2010-3432
The sctp_packet_config function in net/sctp/output.c in the Linux kernel before 2.6.35.6 performs extraneous initializations of packet data structures, which allows remote attackers to cause a denial of service (panic) via a certain sequence of SCTP traffic.
CVE-2010-2962
drivers/gpu/drm/i915/i915_gem.c in the Graphics Execution Manager (GEM) in the Intel i915 driver in the Direct Rendering Manager (DRM) subsystem in the Linux kernel before 2.6.36 does not properly validate pointers to blocks of memory, which allows local users to write to arbitrary kernel memory locations, and consequently gain privileges, via crafted use of the ioctl interface, related to (1) pwrite and (2) pread operations.
CVE-2010-2955
The cfg80211_wext_giwessid function in net/wireless/wext-compat.c in the Linux kernel before 2.6.36-rc3-next-20100831 does not properly initialize certain structure members, which allows local users to leverage an off-by-one error in the ioctl_standard_iw_point function in net/wireless/wext-core.c, and obtain potentially sensitive information from kernel heap memory, via vectors involving an SIOCGIWESSID ioctl call that specifies a large buffer size.
CVE-2010-3705
The sctp_auth_asoc_get_hmac function in net/sctp/auth.c in the Linux kernel before 2.6.36 does not properly validate the hmac_ids array of an SCTP peer, which allows remote attackers to cause a denial of service (memory corruption and panic) via a crafted value in the last element of this array.
CVE-2010-3084
Buffer overflow in the niu_get_ethtool_tcam_all function in drivers/net/niu.c in the Linux kernel before 2.6.36-rc4 allows local users to cause a denial of service or possibly have unspecified other impact via the ETHTOOL_GRXCLSRLALL ethtool command.
CVE-2010-3437
Integer signedness error in the pkt_find_dev_from_minor function in drivers/block/pktcdvd.c in the Linux kernel before 2.6.36-rc6 allows local users to obtain sensitive information from kernel memory or cause a denial of service (invalid pointer dereference and system crash) via a crafted index value in a PKT_CTRL_CMD_STATUS ioctl call.
CVE-2010-3079
kernel/trace/ftrace.c in the Linux kernel before 2.6.35.5, when debugfs is enabled, does not properly handle interaction between mutex possession and llseek operations, which allows local users to cause a denial of service (NULL pointer dereference and outage of all function tracing files) via an lseek call on a file descriptor associated with the set_ftrace_filter file.
CVE-2010-3698
The KVM implementation in the Linux kernel before 2.6.36 does not properly reload the FS and GS segment registers, which allows host OS users to cause a denial of service (host OS crash) via a KVM_RUN ioctl call in conjunction with a modified Local Descriptor Table (LDT).
CVE-2010-3442
Multiple integer overflows in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~100.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~100.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~100.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~100.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~100.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~100.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~100.24.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-100.24.1.el5", rpm:"ofa-2.6.32-100.24.1.el5~1.5.1~4.0.23", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-100.24.1.el5debug", rpm:"ofa-2.6.32-100.24.1.el5debug~1.5.1~4.0.23", rls:"OracleLinux5"))) {
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
