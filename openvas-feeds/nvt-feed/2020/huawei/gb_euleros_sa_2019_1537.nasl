# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1537");
  script_cve_id("CVE-2013-6383", "CVE-2014-3611", "CVE-2014-4667", "CVE-2015-8767", "CVE-2015-8955", "CVE-2015-8970", "CVE-2015-9004", "CVE-2016-5244", "CVE-2017-13693", "CVE-2017-14497", "CVE-2017-15116", "CVE-2017-16529", "CVE-2017-16536", "CVE-2017-16650", "CVE-2017-16939", "CVE-2017-17449", "CVE-2017-9074", "CVE-2018-10323", "CVE-2018-1130", "CVE-2018-8087");
  script_tag(name:"creation_date", value:"2020-01-23 12:08:31 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-01 17:05:19 +0000 (Thu, 01 Jun 2017)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1537)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1537");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1537");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1537 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow was discovered in tpacket_rcv() function in the Linux kernel since v4.6-rc1 through v4.13. A number of socket-related syscalls can be made to set up a configuration when each packet received by a network interface can cause writing up to 10 bytes to a kernel memory outside of a kernel buffer. This can cause unspecified kernel data corruption effects, including damage of in-memory and on-disk XFS data.(CVE-2017-14497)

The qmi_wwan_bind function in drivers
et/usb/qmi_wwan.c in the Linux kernel through 4.13.11 allows local users to cause a denial of service (divide-by-zero error and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16650)

A race condition flaw was found in the way the Linux kernel's SCTP implementation handled sctp_accept() during the processing of heartbeat timeout events. A remote attacker could use this flaw to prevent further connections to be accepted by the SCTP server running on the system, resulting in a denial of service.(CVE-2015-8767)

A race condition flaw was found in the way the Linux kernel's KVM subsystem handled PIT (Programmable Interval Timer) emulation. A guest user who has access to the PIT I/O ports could use this flaw to crash the host.(CVE-2014-3611)

The Linux kernel is vulnerable to a memory leak in the drivers
et/wireless/mac80211_hwsim.c:hwsim_new_radio_nl() function. An attacker could exploit this to cause a potential denial of service.(CVE-2018-8087)

An integer underflow flaw was found in the way the Linux kernel's Stream Control Transmission Protocol (SCTP) implementation processed certain COOKIE_ECHO packets. By sending a specially crafted SCTP packet, a remote attacker could use this flaw to prevent legitimate connections to a particular SCTP server socket to be made.(CVE-2014-4667)

The cx231xx_usb_probe function in drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux kernel through 4.13.11 allows local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16536)

The snd_usb_create_streams function in sound/usb/card.c in the Linux kernel, before 4.13.6, allows local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16529)

A flaw was found in the Linux kernel's random number generator API. A null pointer dereference in the rngapi_reset function may result in denial of service, crashing the system.(CVE-2017-15116)

The __netlink_deliver_tap_skb function in net
etlink/af_netlink.c in the Linux kernel, through 4.14.4, does not restrict observations of Netlink messages to a single net namespace, when CONFIG_NLMON is enabled. This allows local users to obtain sensitive information by leveraging the CAP_NET_ADMIN capability to sniff an nlmon interface for all Netlink ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.1.0.");

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

if(release == "EULEROSVIRTARM64-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
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
