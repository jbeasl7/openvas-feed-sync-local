# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833726");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-1077", "CVE-2023-1249", "CVE-2023-2002", "CVE-2023-3090", "CVE-2023-3141", "CVE-2023-3159", "CVE-2023-3161", "CVE-2023-3268", "CVE-2023-3358", "CVE-2023-35788", "CVE-2023-35823", "CVE-2023-35824", "CVE-2023-35828");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:19 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:41:39 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2023:2859-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2859-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XGJJJR6NHRR7CML5GKMPIEH6Q6AKCX7W");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2023:2859-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security
  and bugfixes.

  The following security bugs were fixed:

  * CVE-2023-1077: Fixed a type confusion in pick_next_rt_entity(), that could
      cause memory corruption (bsc#1208600).

  * CVE-2023-1249: Fixed a use-after-free flaw in the core dump subsystem that
      allowed a local user to crash the system (bsc#1209039).

  * CVE-2023-2002: Fixed a flaw that allowed an attacker to unauthorized
      execution of management commands, compromising the confidentiality,
      integrity, and availability of Bluetooth communication (bsc#1210533).

  * CVE-2023-3090: Fixed a heap out-of-bounds write in the ipvlan network driver
      (bsc#1212842).

  * CVE-2023-3141: Fixed a use-after-free flaw in r592_remove in
      drivers/memstick/host/r592.c, that allowed local attackers to crash the
      system at device disconnect (bsc#1212129).

  * CVE-2023-3159: Fixed use-after-free issue in driver/firewire in
      outbound_phy_packet_callback (bsc#1212128).

  * CVE-2023-3161: Fixed shift-out-of-bounds in fbcon_set_font() (bsc#1212154).

  * CVE-2023-3268: Fixed an out of bounds (OOB) memory access flaw in
      relay_file_read_start_pos in kernel/relay.c (bsc#1212502).

  * CVE-2023-3358: Fixed a NULL pointer dereference flaw in the Integrated
      Sensor Hub (ISH) driver (bsc#1212606).

  * CVE-2023-35788: Fixed an out-of-bounds write in the flower classifier code
      via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets in fl_set_geneve_opt in
      net/sched/cls_flower.c (bsc#1212504).

  * CVE-2023-35823: Fixed a use-after-free flaw in saa7134_finidev in
      drivers/media/pci/saa7134/saa7134-core.c (bsc#1212494).

  * CVE-2023-35824: Fixed a use-after-free in dm1105_remove in
      drivers/media/pci/dm1105/dm1105.c (bsc#1212501).

  * CVE-2023-35828: Fixed a use-after-free flaw in renesas_usb3_remove in
      drivers/usb/gadget/udc/renesas_usb3.c (bsc#1212513).

  The following non-security bugs were fixed:

  * Also include kernel-docs build requirements for ALP

  * Avoid unsupported tar parameter on SLE12

  * Fix missing top level chapter numbers on SLE12 SP5 (bsc#1212158).

  * Fix usrmerge error (boo#1211796)

  * Generalize kernel-doc build requirements.

  * Move obsolete KMP list into a separate file. The list of obsoleted KMPs
      varies per release, move it out of the spec file.

  * Move setting %%build_html to config.sh

  * Move setting %%split_optional to config.sh

  * Move setting %%supported_modules_check to config.sh

  * Move the kernel-binary conflicts out  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"dtb-aarch64", rpm:"dtb-aarch64~5.3.18~150300.59.127.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-al", rpm:"dtb-al~5.3.18~150300.59.127.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-zte", rpm:"dtb-zte~5.3.18~150300.59.127.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-aarch64", rpm:"dtb-aarch64~5.3.18~150300.59.127.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-al", rpm:"dtb-al~5.3.18~150300.59.127.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-zte", rpm:"dtb-zte~5.3.18~150300.59.127.1", rls:"openSUSELeap15.4"))) {
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