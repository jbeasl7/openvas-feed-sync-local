# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.41010100910298468");
  script_tag(name:"creation_date", value:"2025-09-01 04:10:44 +0000 (Mon, 01 Sep 2025)");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-4e0d9fb468)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-4e0d9fb468");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-4e0d9fb468");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384137");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384154");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388453");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-buildx' package(s) announced via the FEDORA-2025-4e0d9fb468 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to release v0.27.0
- Resolves: rhvz#2388453, rhbz#2384137, rhbz#2384154
- Upstream new features and fixes");

  script_tag(name:"affected", value:"'docker-buildx' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"docker-buildx", rpm:"docker-buildx~0.27.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-buildx-debuginfo", rpm:"docker-buildx-debuginfo~0.27.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-buildx-debugsource", rpm:"docker-buildx-debugsource~0.27.0~1.fc41", rls:"FC41"))) {
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
