# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.510210299101948101");
  script_tag(name:"creation_date", value:"2026-03-05 04:37:00 +0000 (Thu, 05 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-5ff99e948e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-5ff99e948e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-5ff99e948e");
  script_xref(name:"URL", value:"https://github.com/zumba/json-serializer/security/advisories/GHSA-v7m3-fpcr-h7m2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-zumba-json-serializer' package(s) announced via the FEDORA-2026-5ff99e948e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Version 3.2.4**

- Fix serialization of parent class private properties by @Copilot in #71
- Fix fatal error when serializing objects with uninitialized typed properties by @Copilot in #68


----

**Version 3.2.3**

[Security] Added method to restrict which classes can be unserialized.
[Security Advisory GHSA-v7m3-fpcr-h7m2]([link moved to references])");

  script_tag(name:"affected", value:"'php-zumba-json-serializer' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-zumba-json-serializer", rpm:"php-zumba-json-serializer~3.2.4~1.fc43", rls:"FC43"))) {
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
