# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887043");
  script_cve_id("CVE-2023-49084", "CVE-2023-49085", "CVE-2023-49086", "CVE-2023-49088", "CVE-2023-50250", "CVE-2023-51448", "CVE-2024-25641", "CVE-2024-29894", "CVE-2024-31443", "CVE-2024-31444", "CVE-2024-31445", "CVE-2024-31458", "CVE-2024-31459", "CVE-2024-31460", "CVE-2024-34340");
  script_tag(name:"creation_date", value:"2024-06-07 06:34:39 +0000 (Fri, 07 Jun 2024)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 20:44:22 +0000 (Wed, 18 Dec 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-27a594f71d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-27a594f71d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-27a594f71d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255602");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255606");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255667");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280482");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280497");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280500");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280503");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280506");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/blob/release/1.2.27/CHANGELOG");
  script_xref(name:"URL", value:"https://github.com/Cacti/spine/blob/release/1.2.27/CHANGELOG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti, cacti-spine' package(s) announced via the FEDORA-2024-27a594f71d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update cacti and cacti-spine to version 1.2.27. This includes the upstream fixes for many CVEs, including a critical remote code execution bug.

- [links moved to references]");

  script_tag(name:"affected", value:"'cacti, cacti-spine' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.2.27~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.2.27~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debuginfo", rpm:"cacti-spine-debuginfo~1.2.27~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine-debugsource", rpm:"cacti-spine-debugsource~1.2.27~1.fc39", rls:"FC39"))) {
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
