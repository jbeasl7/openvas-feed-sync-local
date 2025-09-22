# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885495");
  script_cve_id("CVE-2023-50784");
  script_tag(name:"creation_date", value:"2023-12-26 02:25:49 +0000 (Tue, 26 Dec 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 16:09:40 +0000 (Thu, 21 Dec 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-7c6c696102)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-7c6c696102");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-7c6c696102");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254828");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254874");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254875");
  script_xref(name:"URL", value:"https://forums.unrealircd.org/viewtopic.php?t=9340");
  script_xref(name:"URL", value:"https://www.unrealircd.org/docs/WebSocket_support");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unrealircd' package(s) announced via the FEDORA-2023-7c6c696102 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# UnrealIRCd 6.1.4

This release fixes a crash issue with websockets in UnrealIRCd 6.1.0 - 6.1.3.

The full advisory with all details is available at: [link moved to references]

## Fixes
 * Crash that can be triggered by users when [Websockets]([link moved to references]) are in use (a listen block with `listen::options::websocket`). This was assigned CVE-2023-50784.
 * In 6.1.3, [Websockets]([link moved to references]) were not working with Chrome and possibly other browsers.");

  script_tag(name:"affected", value:"'unrealircd' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"unrealircd", rpm:"unrealircd~6.1.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrealircd-debuginfo", rpm:"unrealircd-debuginfo~6.1.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrealircd-debugsource", rpm:"unrealircd-debugsource~6.1.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrealircd-maxmind", rpm:"unrealircd-maxmind~6.1.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unrealircd-maxmind-debuginfo", rpm:"unrealircd-maxmind-debuginfo~6.1.4~1.fc39", rls:"FC39"))) {
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
