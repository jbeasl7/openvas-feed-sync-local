# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.1016237992101102101");
  script_cve_id("CVE-2026-25727", "CVE-2026-33056");
  script_tag(name:"creation_date", value:"2026-04-10 05:05:24 +0000 (Fri, 10 Apr 2026)");
  script_version("2026-04-10T06:15:25+0000");
  script_tag(name:"last_modification", value:"2026-04-10 06:15:25 +0000 (Fri, 10 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-24 16:17:11 +0000 (Tue, 24 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-e6237c2efe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-e6237c2efe");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-e6237c2efe");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438126");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2449677");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Changes/golang1.26");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_44_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fido-device-onboard' package(s) announced via the FEDORA-2026-e6237c2efe advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for fido-device-onboard-0.5.5-8.fc43.

##### **Changelog for fido-device-onboard**

```
* Wed Apr 01 2026 Peter Robinson <pbrobinson@fedoraproject.org> - 0.5.5-8
- Rebuild for CVE-2026-25727, CVE-2026-33056

* Sun Mar 15 2026 Benjamin A. Beasley <code@musicinmybrain.net> - 0.5.5-7
- In Fedora, update nix dependency from 0.26 to 0.31

* Mon Feb 02 2026 Maxwell G <maxwell@gtmx.me> - 0.5.5-6
- Rebuild for [link moved to references]

* Fri Jan 16 2026 Fedora Release Engineering <releng@fedoraproject.org> - 0.5.5-5
- Rebuilt for [link moved to references]

* Fri Oct 10 2025 Maxwell G <maxwell@gtmx.me> - 0.5.5-4
- Rebuild for golang 1.25.2

```");

  script_tag(name:"affected", value:"'fido-device-onboard' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"fdo-admin-cli", rpm:"fdo-admin-cli~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-admin-cli-debuginfo", rpm:"fdo-admin-cli-debuginfo~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client", rpm:"fdo-client~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client-debuginfo", rpm:"fdo-client-debuginfo~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-init", rpm:"fdo-init~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-init-debuginfo", rpm:"fdo-init-debuginfo~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-manufacturing-server", rpm:"fdo-manufacturing-server~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-manufacturing-server-debuginfo", rpm:"fdo-manufacturing-server-debuginfo~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-owner-cli", rpm:"fdo-owner-cli~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-owner-cli-debuginfo", rpm:"fdo-owner-cli-debuginfo~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-owner-onboarding-server", rpm:"fdo-owner-onboarding-server~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-owner-onboarding-server-debuginfo", rpm:"fdo-owner-onboarding-server-debuginfo~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-rendezvous-server", rpm:"fdo-rendezvous-server~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-rendezvous-server-debuginfo", rpm:"fdo-rendezvous-server-debuginfo~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fido-device-onboard", rpm:"fido-device-onboard~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fido-device-onboard-debuginfo", rpm:"fido-device-onboard-debuginfo~0.5.5~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fido-device-onboard-debugsource", rpm:"fido-device-onboard-debugsource~0.5.5~8.fc43", rls:"FC43"))) {
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
