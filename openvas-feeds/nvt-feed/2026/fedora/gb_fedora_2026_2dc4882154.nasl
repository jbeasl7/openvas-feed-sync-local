# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.2100994882154");
  script_cve_id("CVE-2026-26076");
  script_tag(name:"creation_date", value:"2026-03-31 04:51:57 +0000 (Tue, 31 Mar 2026)");
  script_version("2026-03-31T06:09:03+0000");
  script_tag(name:"last_modification", value:"2026-03-31 06:09:03 +0000 (Tue, 31 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-23 15:51:55 +0000 (Mon, 23 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-2dc4882154)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-2dc4882154");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-2dc4882154");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2439601");
  script_xref(name:"URL", value:"https://github.com/pendulum-project/ntpd-rs/releases/tag/v1.7.0");
  script_xref(name:"URL", value:"https://github.com/pendulum-project/ntpd-rs/releases/tag/v1.7.1");
  script_xref(name:"URL", value:"https://github.com/pendulum-project/ntpd-rs/security/advisories/GHSA-c7j7-rmvr-fjmv");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntpd-rs' package(s) announced via the FEDORA-2026-2dc4882154 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to version 1.7.1.

Includes the fix for CVE-2026-26076: <[link moved to references]>

Release notes:

- <[link moved to references]>
- <[link moved to references]>");

  script_tag(name:"affected", value:"'ntpd-rs' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"ntpd-rs", rpm:"ntpd-rs~1.7.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpd-rs-debuginfo", rpm:"ntpd-rs-debuginfo~1.7.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpd-rs-debugsource", rpm:"ntpd-rs-debugsource~1.7.1~1.fc42", rls:"FC42"))) {
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
