# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0117.1");
  script_cve_id("CVE-2020-26555", "CVE-2022-2586", "CVE-2023-51779", "CVE-2023-6121", "CVE-2023-6606", "CVE-2023-6610", "CVE-2023-6931", "CVE-2023-6932");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-12 16:21:26 +0000 (Fri, 12 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0117-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240117-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218622");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-January/017660.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:0117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-2586: Fixed a use-after-free which can be triggered when a nft table is deleted (bsc#1202095).
- CVE-2023-6121: Fixed an information leak via dmesg when receiving a crafted packet in the NVMe-oF/TCP subsystem (bsc#1217250).
- CVE-2023-6606: Fixed an out of bounds read in the SMB client when receiving a malformed length from a server (bsc#1217947).
- CVE-2023-6610: Fixed an out of bounds read in the SMB client when printing debug information (bsc#1217946).
- CVE-2023-6931: Fixed an out of bounds write in the Performance Events subsystem when adding a new event (bsc#1214158 bsc#1218258).
- CVE-2023-6932: Fixed a use-after-free issue when receiving an IGMP query packet due to reference count mismanagement (bsc#1218253).
- CVE-2020-26555: Fixed an issue during BR/EDR PIN code pairing in the Bluetooth subsystem that would allow replay attacks (bsc#1179610 bsc#1215237).
- CVE-2023-51779: Fixed a use-after-free issue due to a race condition during Bluetooth message reception (bsc#1218559).

The following non-security bugs were fixed:

- Enabled the LLC counters for 'perf' (perf stat) on the Ice-Lake and Rocket-Lake CPUs (jsc#PED-5023 bsc#1211439).
- Reviewed and added more information to README.SUSE (jsc#PED-5021).
- Enabled multibuild for kernel packages (JSC-SLE#5501, boo#1211226, bsc#1218184).
- Fix termination state for idr_for_each_entry_ul() (bsc#1109837).
- KVM: s390/mm: Properly reset no-dat (bsc#1218057).
- KVM: s390: vsie: fix wrong VIR 37 when MSO is used (bsc#1217936).
- PCI: Disable ATS for specific Intel IPU E2000 devices (bsc#1218622).
- gve: Add XDP DROP and TX support for GQI-QPL format (bsc#1214479).
- gve: Add XDP REDIRECT support for GQI-QPL format (bsc#1214479).
- gve: Changes to add new TX queues (bsc#1214479).
- gve: Control path for DQO-QPL (bsc#1214479).
- gve: Do not fully free QPL pages on prefill errors (bsc#1214479).
- gve: Fix gve interrupt names (bsc#1214479).
- gve: Fixes for napi_poll when budget is 0 (bsc#1214479).
- gve: RX path for DQO-QPL (bsc#1214479).
- gve: Set default duplex configuration to full (bsc#1214479).
- gve: Tx path for DQO-QPL (bsc#1214479).
- gve: Unify duplicate GQ min pkt desc size constants (bsc#1214479).
- gve: XDP support GQI-QPL: helper function changes (bsc#1214479).
- gve: fix frag_list chaining (bsc#1214479).
- gve: trivial spell fix Recive to Receive (bsc#1214479).
- gve: unify driver name usage (bsc#1214479).
- net/tg3: fix race condition in tg3_reset_task() (bsc#1217801).
- net/tg3: resolve deadlock in tg3_reset_task() during EEH (bsc#1217801).
- s390/vx: fix save/restore of fpu kernel context (bsc#1218362).
- tracing: Fix a possible race when disabling buffered events (bsc#1217036).
- tracing: Fix a warning when allocating buffered events fails (bsc#1217036).
- tracing: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.189.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.189.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.189.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.189.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.189.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.189.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.189.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.189.1", rls:"SLES12.0SP5"))) {
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
