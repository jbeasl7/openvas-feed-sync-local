# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0206.1");
  script_cve_id("CVE-2024-6126");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-03 15:15:06 +0000 (Wed, 03 Jul 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0206-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0206-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CNZTH7PKY4BMSDPSUA32JS3BZQRTKTGF/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227299");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cockpit' package(s) announced via the openSUSE-SU-2024:0206-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cockpit fixes the following issues:

- new version 320:

 * pam-ssh-add: Fix insecure killing of session ssh-agent
 (boo#1226040, CVE-2024-6126)

- changes in older versions:

 * Storage: Btrfs snapshots
 * Podman: Add image pull action
 * Files: Bookmark support
 * webserver: System user changes
 * Metrics: Grafana setup now prefers Valkey
- Invalid json against the storaged manifest boo#1227299");

  script_tag(name:"affected", value:"'cockpit' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"cockpit", rpm:"cockpit~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-bridge", rpm:"cockpit-bridge~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-devel", rpm:"cockpit-devel~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-doc", rpm:"cockpit-doc~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-kdump", rpm:"cockpit-kdump~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-networkmanager", rpm:"cockpit-networkmanager~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-packagekit", rpm:"cockpit-packagekit~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-pcp", rpm:"cockpit-pcp~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-selinux", rpm:"cockpit-selinux~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-storaged", rpm:"cockpit-storaged~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-system", rpm:"cockpit-system~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cockpit-ws", rpm:"cockpit-ws~320~bp156.2.6.3", rls:"openSUSELeap15.6"))) {
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
