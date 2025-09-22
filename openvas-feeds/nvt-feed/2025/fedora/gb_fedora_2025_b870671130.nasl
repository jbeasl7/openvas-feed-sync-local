# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.98870671130");
  script_cve_id("CVE-2025-32801", "CVE-2025-32802", "CVE-2025-32803");
  script_tag(name:"creation_date", value:"2025-06-20 04:08:54 +0000 (Fri, 20 Jun 2025)");
  script_version("2025-06-20T05:40:42+0000");
  script_tag(name:"last_modification", value:"2025-06-20 05:40:42 +0000 (Fri, 20 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-28 17:15:23 +0000 (Wed, 28 May 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-b870671130)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b870671130");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b870671130");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2324168");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2368989");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2369336");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2369380");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2370278");
  script_xref(name:"URL", value:"https://downloads.isc.org/isc/kea/2.6.3/Kea-2.6.3-ReleaseNotes.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kea' package(s) announced via the FEDORA-2025-b870671130 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- New version 2.6.3 (rhbz#2368989)
- Fix for: CVE-2025-32801, CVE-2025-32802, CVE-2025-32803
- kea.conf: Remove /tmp/ from socket-name for existing configurations
- kea.conf: Set pseudo-random password for default config to secure fresh
 install and allow CA startup without user intervention
- kea.conf: Restrict directory permissions
- Sync service files with upstream
- Fix leases ownership when switching from root to kea user (rhbz#2324168)

Release Notes:

The new default configuration file, kea-ctrl-agent.conf, introduces an authentication setting, 'password-file', which restricts access to the REST API. On Fedora, the kea-api-password file is automatically populated with a pseudo-random password to secure new installations.

For system upgrades, it is strongly recommended to update any custom configurations to restrict access to the REST API.

For more details, including information on CVE fixes and incompatible changes, refer to the upstream release notes:

[link moved to references]");

  script_tag(name:"affected", value:"'kea' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"kea", rpm:"kea~2.6.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-debuginfo", rpm:"kea-debuginfo~2.6.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-debugsource", rpm:"kea-debugsource~2.6.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-devel", rpm:"kea-devel~2.6.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-doc", rpm:"kea-doc~2.6.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-hooks", rpm:"kea-hooks~2.6.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-hooks-debuginfo", rpm:"kea-hooks-debuginfo~2.6.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-keama", rpm:"kea-keama~2.6.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-keama-debuginfo", rpm:"kea-keama-debuginfo~2.6.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-libs", rpm:"kea-libs~2.6.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kea-libs-debuginfo", rpm:"kea-libs-debuginfo~2.6.3~1.fc41", rls:"FC41"))) {
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
