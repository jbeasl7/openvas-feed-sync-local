# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.10291002152328");
  script_tag(name:"creation_date", value:"2026-03-27 04:50:29 +0000 (Fri, 27 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-f9d2152328)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-f9d2152328");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-f9d2152328");
  script_xref(name:"URL", value:"https://lib.openmpt.org/libopenmpt/2026/03/24/security-updates-0.8.6-0.7.19-0.6.28-0.5.42-0.4.54/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libopenmpt' package(s) announced via the FEDORA-2026-f9d2152328 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update from 0.8.5 to 0.8.6 to fix regression:
[link moved to references]");

  script_tag(name:"affected", value:"'libopenmpt' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt", rpm:"libopenmpt~0.8.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-debuginfo", rpm:"libopenmpt-debuginfo~0.8.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-debugsource", rpm:"libopenmpt-debugsource~0.8.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenmpt-devel", rpm:"libopenmpt-devel~0.8.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpt123", rpm:"openmpt123~0.8.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpt123-debuginfo", rpm:"openmpt123-debuginfo~0.8.6~1.fc43", rls:"FC43"))) {
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
