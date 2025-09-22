# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123561");
  script_cve_id("CVE-2012-4398");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:33 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1348)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1348");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1348.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-371.el5, oracleasm-2.6.18-371.el5' package(s) announced via the ELSA-2013-1348 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-371]
- [net] be2net: enable polling prior enabling interrupts globally (Ivan Vecera) [987539]

[2.6.18-370]
- [net] be2net: Fix to avoid hardware workaround when not needed (Ivan Vecera) [995961]
- [kernel] signals: stop info leak via tkill and tgkill syscalls (Oleg Nesterov) [970875] {CVE-2013-2141}

[2.6.18-369]
- [fs] nlm: Ensure we resend pending blocking locks after a reclaim (Steve Dickson) [918592]
- [kernel] kmod: kthread_run causes oom killer deadlock (Frantisek Hrbata) [983506]
- [fs] nfs4: ratelimit some messages, add name to bad seq-id mess (Dave Wysochanski) [953121]
- [fs] nfsd: fix EXDEV checking in rename (J. Bruce Fields) [515599]
- [misc] tty: Fix abusers of current-sighand->tty (Aaron Tomlin) [858981]
- [net] ipv6: don't call addrconf_dst_alloc again when enable lo (Jiri Benc) [981417]
- [redhat] kabi: Adding symbol fc_fabric_login (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fcoe_ctlr_recv (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_exch_mgr_reset (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_lport_init (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_exch_recv (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_lport_destroy (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fcoe_ctlr_els_send (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fcoe_ctlr_destroy (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_exch_init (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_fabric_logoff (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_set_mfs (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_elsct_init (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fcoe_ctlr_link_up (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fcoe_ctlr_recv_flogi (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_change_queue_depth (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fcoe_ctlr_init (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fcoe_ctlr_link_down (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_change_queue_type (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_exch_mgr_free (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_exch_mgr_alloc (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_lport_config (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_disc_init (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol strict_strtoul (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_rport_init (Jiri Olsa) [864256]
- [redhat] kabi: Adding symbol fc_get_host_port_state (Jiri Olsa) [864256]

[2.6.18-368]
- [net] tg3: Add read dma workaround for 5720 (Ivan Vecera) [984064]
- [net] tg3: Add New 5719 Read DMA workaround (Ivan Vecera) [984064]
- [net] vlan: fix perf regression due to missing features flags (Michal Schmidt) [977711]

[2.6.18-367]
- [net] ipv6: do udp_push_pending_frames AF_INET sock pending data (Jiri Benc) [987648] {CVE-2013-4162}
- [net] mlx4: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-371.el5, oracleasm-2.6.18-371.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~371.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~371.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~371.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~371.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~371.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~371.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~371.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~371.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~371.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~371.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.el5", rpm:"ocfs2-2.6.18-371.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.el5PAE", rpm:"ocfs2-2.6.18-371.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.el5debug", rpm:"ocfs2-2.6.18-371.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-371.el5xen", rpm:"ocfs2-2.6.18-371.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.el5", rpm:"oracleasm-2.6.18-371.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.el5PAE", rpm:"oracleasm-2.6.18-371.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.el5debug", rpm:"oracleasm-2.6.18-371.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-371.el5xen", rpm:"oracleasm-2.6.18-371.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
