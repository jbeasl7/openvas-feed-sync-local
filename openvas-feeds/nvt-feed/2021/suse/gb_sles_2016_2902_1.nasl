# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2902.1");
  script_cve_id("CVE-2016-7161", "CVE-2016-7170", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-8576", "CVE-2016-8577", "CVE-2016-8578", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:03 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-05 17:40:55 +0000 (Wed, 05 Oct 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2902-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2902-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162902-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998516");
  script_xref(name:"URL", value:"https://gitlab.suse.de/virtualization/qemu.git");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-November/002419.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2016:2902-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kvm fixes the following issues:

- Address various security/stability issues
 * Fix OOB access in xlnx.xpx-ethernetlite emulation (CVE-2016-7161 bsc#1001151)
 * Fix OOB access in VMware SVGA emulation (CVE-2016-7170 bsc#998516)
 * Fix DOS in ColdFire Fast Ethernet Controller emulation
 (CVE-2016-7908 bsc#1002550)
 * Fix DOS in USB xHCI emulation (CVE-2016-8576 bsc#1003878)
 * Fix DOS in virtio-9pfs (CVE-2016-8578 bsc#1003894)
 * Fix DOS in virtio-9pfs (CVE-2016-9105 bsc#1007494)
 * Fix DOS in virtio-9pfs (CVE-2016-8577 bsc#1003893)
 * Plug data leak in virtio-9pfs interface (CVE-2016-9103 bsc#1007454)
 * Fix DOS in virtio-9pfs interface (CVE-2016-9102 bsc#1007450)
 * Fix DOS in virtio-9pfs (CVE-2016-9106 bsc#1007495)
 * Fix DOS in 16550A UART emulation (CVE-2016-8669 bsc#1004707)
 * Fix DOS in PC-Net II emulation (CVE-2016-7909 bsc#1002557)
 * Fix DOS in PRO100 emulation (CVE-2016-9101 bsc#1007391)
 * Fix DOS in RTL8139 emulation (CVE-2016-8910 bsc#1006538)
 * Fix DOS in Intel HDA controller emulation (CVE-2016-8909 bsc#1006536)
 * Fix DOS in virtio-9pfs (CVE-2016-9104 bsc#1007493)
 * Fix DOS in JAZZ RC4030 emulation (CVE-2016-8667 bsc#1004702)

- Patch queue updated from [link moved to references] SLE11-SP4
- Remove semi-contradictory and now determined erroneous statement
 in kvm-supported.txt regarding not running ntp in kvm guest when
 kvm-clock is used. It is now recommended to use ntp in guest in
 this case.");

  script_tag(name:"affected", value:"'kvm' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~50.1", rls:"SLES11.0SP4"))) {
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
