# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.429101100102210099102");
  script_cve_id("CVE-2025-67603", "CVE-2025-67858");
  script_tag(name:"creation_date", value:"2026-01-12 04:26:16 +0000 (Mon, 12 Jan 2026)");
  script_version("2026-01-12T05:50:06+0000");
  script_tag(name:"last_modification", value:"2026-01-12 05:50:06 +0000 (Mon, 12 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-429edf2dcf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-429edf2dcf");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-429edf2dcf");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'foomuuri' package(s) announced via the FEDORA-2026-429edf2dcf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upstream update to v0.31 with fixes to CVE-2025-67603 and CVE-2025-67858.

* CVE-2025-67603: Add PolicyKit authorization to D-Bus methods.
* CVE-2025-67858: Verify `interface` input parameter on D-Bus methods.
* Security hardening:
 * Add `ProtectSystem=full` to all systemd service files. This changes `/etc`
 to read-only for all Foomuuri processes. Make sure you don't write any
 state files there in your startup hook or Foomuuri Monitor event hook.
 * Change umask to 022 when using `--fork` to fork as a background daemon
 process.
 * More strict IP address verify for iplist entries.");

  script_tag(name:"affected", value:"'foomuuri' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"foomuuri", rpm:"foomuuri~0.31~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"foomuuri-firewalld", rpm:"foomuuri-firewalld~0.31~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"foomuuri_exporter", rpm:"foomuuri_exporter~0.31~1.fc43", rls:"FC43"))) {
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
