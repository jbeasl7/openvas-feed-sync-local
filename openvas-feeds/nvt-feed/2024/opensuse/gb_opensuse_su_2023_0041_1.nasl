# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833753");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-48257", "CVE-2022-48258");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-23 19:09:19 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:12:31 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for EternalTerminal (openSUSE-SU-2023:0041-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0041-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/T2VTENKRMSWIB6OVIPA263AB3ABXCRJT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'EternalTerminal'
  package(s) announced via the openSUSE-SU-2023:0041-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for EternalTerminal fixes the following issues:

     EternalTerminal was updated to 6.2.4:

  * CVE-2022-48257, CVE-2022-48258 remedied

  * fix readme regarding port forwarding #522

  * Fix test failures that started appearing in CI #526

  * Add documentation for the EternalTerminal protocol #523

  * ssh-et: apply upstream updates #527

  * docs: write gpg key to trusted.gpg.d for APT #530

  * Support for ipv6 addresses (with or without port specified) #536

  * ipv6 abbreviated address support #539

  * Fix launchd plist config to remove daemonization. #540

  * Explicitly set verbosity from cxxopts value. #542

  * Remove daemon flag in systemd config #549

  * Format all source with clang-format. #552

  * Fix tunnel parsing exception handling. #550

  * Fix SIGTERM behavior that causes systemd control of etserver to
         timeout. #554

  * Parse telemetry ini config as boolean and make telemetry opt-in. #553

  * Logfile open mode and permission plus location configurability. #556

  - boo#1207123 (CVE-2022-48257) Fix predictable logfile names in /tmp

  - boo#1207124 (CVE-2022-48258) Fix etserver and etclient have
       world-readable logfiles

  - Note: Upstream released 6.2.2 with fixes then 6.2.4 and later removed
       6.2.2 and redid 6.2.4");

  script_tag(name:"affected", value:"'EternalTerminal' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"EternalTerminal", rpm:"EternalTerminal~6.2.4~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"EternalTerminal", rpm:"EternalTerminal~6.2.4~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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