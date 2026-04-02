# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20576.1");
  script_cve_id("CVE-2025-13465");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-17 17:10:07 +0000 (Tue, 17 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20576-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20576-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620576-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257325");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024625.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cockpit, cockpit-machines' package(s) announced via the SUSE-SU-2026:20576-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cockpit-machines, cockpit fixes the following issues:

- CVE-2025-13465: Update the lodash dependencie to avoid prototype pollution. (bsc#1257324)

Changes in cockpit-machines:

- Update to 346
 * 346
 - Performance improvements
 - Translation updates
 * 345
 - New virtual machines don't get SPICE graphics anymore
 - Support for network port forwarding
 - Bug fixes and translation updates

- Update to 344
 * 344
 - Port forwarding for user session VMs
 - 'Shutdown and restart' action
 - Faster startup
 * 343
 - Memory usage now shows numbers reported by the guest (RHEL-116731)

- Update to 342
 * 342
 - Bug fixes and translation updates
 * 341
 - Improved UX for Disks and Network interface tables
 - Bug fixes and translation updates
 * 340
 - Use exclusive VNC connections with 'Remote resizing'

- Update to 339
 * 339
 - Serial consoles now keep their content and stay alive
 - No longer copies qemu.conf values into VM definitions
 * 338
 - Translation and dependency updates
 - Detachable VNC console

- Update to 337
 * 337
 - Bug fixes and translation updates
 * 336
 - Graphical VNC and serial consoles improvements
 - Control VNC console resizing and scaling
 - Bug fixes and translation updates
 * 335
 - Bug fixes and translation updates
 * 334
 - Bug fixes and translation updates

Changes in cockpit:

- Update to 354
 * changes since 351
 - 354
 * Convert documentation to AsciiDoc
 * Work around Firefox 146/147 bug (rhbz#2422331)
 * Bug fixes
 - 353
 * Networking: Suggest prefix length and gateway address
 * Bug fixes and translation updates
 - 352
 * Shown a warning if the last shutdown/reboot was unclean
 * Bug fixes and translation updates

- Update to 351
 * Changes since 349
 - 351
 * Firewall ports can be deleted individually
 - 350
 * networking: fix renaming of bridges and other groups (RHEL-117883)
 * bridge: fix OpenSSH_10.2p1 host key detection

- Update to 349
 * Changes since 346
 - 349
 * Package manifests: add any test
 * Bug fixes and translation updates
 - 348
 * Bug fixes and translation updates
 - 347
 * Site-specific branding support

- Update to 346
 * Changes since 344
 - 346
 * Support branding Cockpit pages
 * Storage: Support for Stratis 'V2' pools
 - 345
 * Translation and dependency updates
 * Shorter IPv6 addresses
 * IPv6 addresses for WireGuard

- Update to 344
 * Changes since 340
 - 344
 * Bug fixes and translation updates
 - 343
 * login: Improve error message for unsupported shells
 * cockpit: Handle file access issues with files in machines.d
 * Translation updates
 - 342
 * systemd: ensure update() is called at least once for tuned-dialog
 * Translation updates
 - 341
 * services: show link to podman page for quadlets
 * Bug fixes and translation updates");

  script_tag(name:"affected", value:"'cockpit, cockpit-machines' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"cockpit", rpm:"cockpit~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-bridge", rpm:"cockpit-bridge~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-devel", rpm:"cockpit-devel~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-doc", rpm:"cockpit-doc~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-firewalld", rpm:"cockpit-firewalld~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-kdump", rpm:"cockpit-kdump~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-machines", rpm:"cockpit-machines~346~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-networkmanager", rpm:"cockpit-networkmanager~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-packagekit", rpm:"cockpit-packagekit~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-selinux", rpm:"cockpit-selinux~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-storaged", rpm:"cockpit-storaged~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-system", rpm:"cockpit-system~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-ws", rpm:"cockpit-ws~354~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-ws-selinux", rpm:"cockpit-ws-selinux~354~160000.1.1", rls:"SLES16.0.0"))) {
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
