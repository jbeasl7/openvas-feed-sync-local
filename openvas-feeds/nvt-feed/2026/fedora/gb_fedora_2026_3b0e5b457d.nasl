# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.3980101598457100");
  script_cve_id("CVE-2025-46728", "CVE-2025-53629", "CVE-2025-66570", "CVE-2025-66577", "CVE-2026-21428", "CVE-2026-22776");
  script_tag(name:"creation_date", value:"2026-01-22 04:25:15 +0000 (Thu, 22 Jan 2026)");
  script_version("2026-01-23T05:49:25+0000");
  script_tag(name:"last_modification", value:"2026-01-23 05:49:25 +0000 (Fri, 23 Jan 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-10 15:02:46 +0000 (Wed, 10 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2026-3b0e5b457d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-3b0e5b457d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-3b0e5b457d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2364284");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2379431");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419548");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419631");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2426699");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2428893");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/releases/tag/v0.30.1");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/security/advisories/GHSA-gfpf-r66f-5mh2");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/security/advisories/GHSA-h934-98h4-j43q");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/security/advisories/GHSA-wpc6-j37r-jcx7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cpp-httplib' package(s) announced via the FEDORA-2026-3b0e5b457d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Update to 0.30.1

- [Denial of service (DOS) using zip bomb (CVE-2026-22776)]([link moved to references])
- [CRLF injection in http headers (CVE-2026-21428)]([link moved to references])
- [Untrusted HTTP Header Handling: X-Forwarded-For/X-Real-IP Trust (CVE-2025-66577)]([link moved to references])

[link moved to references]");

  script_tag(name:"affected", value:"'cpp-httplib' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"cpp-httplib", rpm:"cpp-httplib~0.30.1~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp-httplib-devel", rpm:"cpp-httplib-devel~0.30.1~5.fc42", rls:"FC42"))) {
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
