# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123045");
  script_cve_id("CVE-2014-8989");
  script_tag(name:"creation_date", value:"2015-10-06 06:47:04 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-3064)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-3064");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-3064.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-98.el6uek, dtrace-modules-3.8.13-98.el7uek, kernel-uek' package(s) announced via the ELSA-2015-3064 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-98]
- KVM: x86: SYSENTER emulation is broken (Nadav Amit) [Orabug: 21502729] {CVE-2015-0239} {CVE-2015-0239}
- fs: take i_mutex during prepare_binprm for set[ug]id executables (Jann Horn) [Orabug: 21502159] {CVE-2015-3339}

[3.8.13-97]
- add ql2400, ql2500 firmware versions to prerequisites (Dan Duval) [Orabug: 21474929]
- correct QLogic firmware dependencies in the spec file (Dan Duval) [Orabug: 21474929]

[3.8.13-96]
- xen-blkfront: don't add indirect page to list when !feature_persistent (Bob Liu) [Orabug: 21459266]

[3.8.13-95]
- add firmware dependencies to spec files (Dan Duval) [Orabug: 21417522]

[3.8.13-94]
- ipv6: Don't reduce hop limit for an interface (D.S. Ljungmark) [Orabug: 21444784] {CVE-2015-2922}
- ipv4: Missing sk_nulls_node_init() in ping_unhash(). (David S. Miller) [Orabug: 21444685] {CVE-2015-3636}

[3.8.13-93]
- config: sync up config files to make build clean (Guangyu Sun) [Orabug: 21425838]
- acpi: fix typo in drivers/acpi/osl.c (Guangyu Sun) [Orabug: 21418329]

[3.8.13-92]
- Revert 'i40e: Add support for getlink, setlink ndo ops' (Brian Maly) [Orabug: 21314906]
- x86: Do not try to sync identity map for non-mapped pages (Dave Hansen) [Orabug: 21326516]

[3.8.13-91]
- rds: re-entry of rds_ib_xmit/rds_iw_xmit (Wengang Wang) [Orabug: 21324074]
- drm/mgag200: Reject non-character-cell-aligned mode widths (Adam Jackson) [Orabug: 20868823]
- drm/mgag200: fix typo causing bw limits to be ignored on some chips (Dave Airlie) [Orabug: 20868823]
- drm/mgag200: remove unused driver_private access (David Herrmann) [Orabug: 20868823]
- drm/mgag200: Invalidate page tables when pinning a BO (Egbert Eich) [Orabug: 20868823]
- drm/mgag200: Fix LUT programming for 16bpp (Egbert Eich) [Orabug: 20868823]
- drm/mgag200: Fix framebuffer pitch calculation (Takashi Iwai) [Orabug: 20868823]
- drm/mgag200: Add sysfs support for connectors (Egbert Eich) [Orabug: 20868823]
- drm/mgag200: Add an crtc_disable callback to the crtc helper funcs (Egbert Eich) [Orabug: 20868823]
- drm/mgag200: Fix logic in mgag200_bo_pin() (v2) (Egbert Eich) [Orabug: 20868823]
- drm/mgag200: inline reservations (Maarten Lankhorst) [Orabug: 20868823]
- drm/mgag200: do not attempt to acquire a reservation while in an interrupt handler (Maarten Lankhorst) [Orabug: 20868823]
- drm/mgag200: Added resolution and bandwidth limits for various G200e products. (Julia Lemire) [Orabug: 20868823]
- drm/mgag200: Reject modes that are too big for VRAM (Christopher Harvey) [Orabug: 20868823]
- drm/mgag200: Don't do full cleanup if mgag200_device_init fails (Christopher Harvey) [Orabug: 20868823]
- drm/mgag200: Hardware cursor support (Christopher Harvey) [Orabug: 20868823]
- drm/mgag200: Add missing write to index before accessing data register (Christopher Harvey) [Orabug: 20868823]
- drm/mgag200: Fix framebuffer base address programming (Christopher Harvey) [Orabug: 20868823]
- drm/mgag200: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-98.el6uek, dtrace-modules-3.8.13-98.el7uek, kernel-uek' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-98.el6uek", rpm:"dtrace-modules-3.8.13-98.el6uek~0.4.5~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-provider-headers", rpm:"dtrace-modules-provider-headers~0.4.5~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-shared-headers", rpm:"dtrace-modules-shared-headers~0.4.5~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~98.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~98.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~98.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~98.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~98.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~98.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-98.el7uek", rpm:"dtrace-modules-3.8.13-98.el7uek~0.4.5~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-provider-headers", rpm:"dtrace-modules-provider-headers~0.4.5~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-shared-headers", rpm:"dtrace-modules-shared-headers~0.4.5~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~98.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~98.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~98.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~98.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~98.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~98.el7uek", rls:"OracleLinux7"))) {
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
