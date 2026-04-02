# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.04975319910199101");
  script_cve_id("CVE-2026-32627");
  script_tag(name:"creation_date", value:"2026-04-01 05:00:51 +0000 (Wed, 01 Apr 2026)");
  script_version("2026-04-01T06:13:16+0000");
  script_tag(name:"last_modification", value:"2026-04-01 06:13:16 +0000 (Wed, 01 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-17 19:08:44 +0000 (Tue, 17 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-04a531cece)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-04a531cece");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-04a531cece");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448105");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/releases/tag/v0.37.2");
  script_xref(name:"URL", value:"https://github.com/yhirose/cpp-httplib/security/advisories/GHSA-c3h8-fqq4-xm4g");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cpp-httplib' package(s) announced via the FEDORA-2026-04a531cece advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# Update to 0.37.2

- Fixes silent TLS certificate verification bypass on HTTPS Redirect via
proxy ([CVE-2026-32627]([link moved to references]), rhbz#2448105)

Source: [link moved to references]

[//]: # (#2448104 NEW - davide@cavalca.name - CVE-2026-32627 cpp-httplib: silent TLS certificate verification bypass on HTTPS Redirect via proxy [epel-all])
[//]: # (#2448105 CLOSED - pemensik@redhat.com - CVE-2026-32627 cpp-httplib: silent TLS certificate verification bypass on HTTPS Redirect via proxy [fedora-all])");

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

  if(!isnull(res = isrpmvuln(pkg:"cpp-httplib", rpm:"cpp-httplib~0.37.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpp-httplib-devel", rpm:"cpp-httplib-devel~0.37.2~1.fc42", rls:"FC42"))) {
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
