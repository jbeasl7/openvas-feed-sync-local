# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.61011009996510197102");
  script_cve_id("CVE-2026-28434", "CVE-2026-28435", "CVE-2026-29076", "CVE-2026-31870");
  script_tag(name:"creation_date", value:"2026-03-23 04:48:32 +0000 (Mon, 23 Mar 2026)");
  script_version("2026-03-23T06:04:31+0000");
  script_tag(name:"last_modification", value:"2026-03-23 06:04:31 +0000 (Mon, 23 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-6ed9c65eaf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-6ed9c65eaf");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-6ed9c65eaf");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2441656");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2444636");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2444638");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445663");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445943");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2446926");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/compare/v0.32.0...v0.37.0");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/security/advisories/GHSA-39q5-hh6x-jpxx");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/security/advisories/GHSA-8mpw-r4gc-xm7q");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/security/advisories/GHSA-qq6v-r583-3h69");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/security/advisories/GHSA-xvfx-w463-6fpp");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cpp-httplib' package(s) announced via the FEDORA-2026-6ed9c65eaf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Update to 0.37.1 (rbhz#2445943)

- Fixes Denial of Service via malformed Content-Length header
 ([CVE-2026-31870]([link moved to references])
- Reenables 32-bit build

# Update to 0.37.0 (rhbz#2441656)

- Fixes Denial of Service via crafted HTTP POST request ([CVE-2026-29076]([link moved to references]), rhbz#2445663)

## Update to 0.35.0

- Payload size limit bypass via gzip decompression in ContentReader (streaming) allows oversized request bodies ([CVE-2026-28435]([link moved to references]), rhbz#2444638)
- Default exception handler leaks e.what() to clients via EXCEPTION_WHAT response header ([CVE-2026-28434]([link moved to references]), rhbz#2444636)

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

  if(!isnull(res = isrpmvuln(pkg:"cpp-httplib", rpm:"cpp-httplib~0.37.1~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp-httplib-devel", rpm:"cpp-httplib-devel~0.37.1~2.fc42", rls:"FC42"))) {
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
