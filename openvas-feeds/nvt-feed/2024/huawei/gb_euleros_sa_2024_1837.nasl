# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1837");
  script_cve_id("CVE-2021-47037", "CVE-2021-47070", "CVE-2021-47076", "CVE-2021-47094", "CVE-2021-47101", "CVE-2021-47105", "CVE-2021-47182", "CVE-2021-47212", "CVE-2023-52467", "CVE-2023-52476", "CVE-2023-52478", "CVE-2023-52484", "CVE-2023-52486", "CVE-2023-52492", "CVE-2023-52498", "CVE-2023-52515", "CVE-2023-52522", "CVE-2023-52527", "CVE-2023-52572", "CVE-2023-52578", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52597", "CVE-2023-52598", "CVE-2023-52612", "CVE-2023-52615", "CVE-2023-52616", "CVE-2023-52619", "CVE-2023-52620", "CVE-2023-52621", "CVE-2023-52622", "CVE-2023-52623", "CVE-2024-23307", "CVE-2024-23851", "CVE-2024-24855", "CVE-2024-24860", "CVE-2024-24861", "CVE-2024-25739", "CVE-2024-26614", "CVE-2024-26627", "CVE-2024-26633", "CVE-2024-26635", "CVE-2024-26640", "CVE-2024-26641", "CVE-2024-26642", "CVE-2024-26643", "CVE-2024-26645", "CVE-2024-26654", "CVE-2024-26656", "CVE-2024-26659", "CVE-2024-26661", "CVE-2024-26663", "CVE-2024-26665", "CVE-2024-26668", "CVE-2024-26669", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26675", "CVE-2024-26679", "CVE-2024-26680", "CVE-2024-26686", "CVE-2024-26688", "CVE-2024-26689", "CVE-2024-26695", "CVE-2024-26698", "CVE-2024-26704", "CVE-2024-26720", "CVE-2024-26733", "CVE-2024-26734", "CVE-2024-26735", "CVE-2024-26739", "CVE-2024-26740", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26747", "CVE-2024-26752", "CVE-2024-26759", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26769", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26787", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26808", "CVE-2024-26809", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-26813", "CVE-2024-26833", "CVE-2024-26835", "CVE-2024-26840", "CVE-2024-26851", "CVE-2024-26855", "CVE-2024-26859", "CVE-2024-26862", "CVE-2024-26870", "CVE-2024-26872", "CVE-2024-26875", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26885", "CVE-2024-26889", "CVE-2024-26894", "CVE-2024-26900", "CVE-2024-26901", "CVE-2024-26920", "CVE-2024-27437");
  script_tag(name:"creation_date", value:"2024-06-25 04:14:08 +0000 (Tue, 25 Jun 2024)");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-29 20:02:49 +0000 (Mon, 29 Apr 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-1837)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1837");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1837");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-1837 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: IB/ipoib: Fix mcast list locking Releasing the `priv->lock` while iterating the `priv->multicast_list` in `ipoib_mcast_join_task()` opens a window for `ipoib_mcast_dev_flush()` to remove the items while in the middle of iteration. If the mcast is removed while the lock was dropped, the for loop spins forever resulting in a hard lockup.(CVE-2023-52587)In the Linux kernel, the following vulnerability has been resolved: scsi: core: Move scsi_host_busy() out of host lock for waking up EH handler Inside scsi_eh_wakeup(), scsi_host_busy() is called & checked with host lock every time for deciding if error handler kthread needs to be waken up. This can be too heavy in case of recovery, such as: - N hardware queues - queue depth is M for each hardware queue - each scsi_host_busy() iterates over (N * M) tag/requests If recovery is triggered in case that all requests are in-flight, each scsi_eh_wakeup() is strictly serialized, when scsi_eh_wakeup() is called for the last in-flight request, scsi_host_busy() has been run for (N * M - 1) times, and request has been iterated for (N*M - 1) * (N * M) times. If both N and M are big enough, hard lockup can be triggered on acquiring host lock, and it is observed on mpi3mr(128 hw queues, queue depth 8169). Fix the issue by calling scsi_host_busy() outside the host lock. We don't need the host lock for getting busy count because host the lock never covers that. [mkp: Drop unnecessary 'busy' variables pointed out by Bart](CVE-2024-26627)copy_params in drivers/md/dm-ioctl.c in the Linux kernel through 6.7.1 can attempt to allocate more than INT_MAX bytes, and crash, because of a missing param_kernel->data_size check. This is related to ctl_ioctl.(CVE-2024-23851)In the Linux kernel, the following vulnerability has been resolved: ipv4, ipv6: Fix handling of transhdrlen in __ip{,6}_append_data() Including the transhdrlen in length is a problem when the packet is partially filled (e.g. something like send(MSG_MORE) happened previously) when appending to an IPv4 or IPv6 packet as we don't want to repeat the transport header or account for it twice. This can happen under some circumstances, such as splicing into an L2TP socket. The symptom observed is a warning in __ip6_append_data(): WARNING: CPU: 1 PID: 5042 at net/ipv6/ip6_output.c:1800 __ip6_append_data.isra.0+0x1be8/0x47f0 net/ipv6/ip6_output.c:1800 that occurs when MSG_SPLICE_PAGES is used to append more data to an already partially occupied skbuff. The warning occurs when 'copy' is larger than the amount of data in the message iterator. This is because the requested length includes the transport header length when it shouldn't. This can be triggered by, for example: sfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_L2TP), bind(sfd, ...), // ::1 connect(sfd, ...), // ::1 port 7 send(sfd, buffer, 4100, MSG_MORE), sendfile(sfd, dfd, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1358.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1358.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1358.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1358.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1358.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1358.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
