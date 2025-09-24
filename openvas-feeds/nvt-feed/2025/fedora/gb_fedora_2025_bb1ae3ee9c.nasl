# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.98981971013101101999");
  script_cve_id("CVE-2025-10500", "CVE-2025-10501", "CVE-2025-10502", "CVE-2025-10585");
  script_tag(name:"creation_date", value:"2025-09-23 04:05:22 +0000 (Tue, 23 Sep 2025)");
  script_version("2025-09-23T05:39:06+0000");
  script_tag(name:"last_modification", value:"2025-09-23 05:39:06 +0000 (Tue, 23 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-bb1ae3ee9c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-bb1ae3ee9c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-bb1ae3ee9c");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2025-bb1ae3ee9c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to 140.0.7339.185
 * CVE-2025-10585: Type Confusion in V8
 * CVE-2025-10500: Use after free in Dawn
 * CVE-2025-10501: Use after free in WebRTC
 * CVE-2025-10502: Heap buffer overflow in ANGLE");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~140.0.7339.185~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~140.0.7339.185~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~140.0.7339.185~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~140.0.7339.185~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~140.0.7339.185~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~140.0.7339.185~1.fc42", rls:"FC42"))) {
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
