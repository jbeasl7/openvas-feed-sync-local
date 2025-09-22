# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886236");
  script_cve_id("CVE-2023-52161", "CVE-2024-28084");
  script_tag(name:"creation_date", value:"2024-03-25 09:36:41 +0000 (Mon, 25 Mar 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-08 15:50:22 +0000 (Wed, 08 Jan 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-3fa713f2e0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-3fa713f2e0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-3fa713f2e0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263573");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264597");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267652");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267710");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iwd' package(s) announced via the FEDORA-2024-3fa713f2e0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"iwd 2.16:

 Fix issue with uninitialized variable and DPP encrypt.
 Fix issue with Access Point mode and ATTR_MAC validation.
 Fix issue with Access Point mode and frequency attributes.
 Fix issue with P2P and handling client info description.
 Fix issue with P2P and handling parsing of service info.
 Fix issue with netconfig and handling domain list.
 Add support for forcing a default ECC group.");

  script_tag(name:"affected", value:"'iwd' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"iwd", rpm:"iwd~2.16~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwd-debuginfo", rpm:"iwd-debuginfo~2.16~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwd-debugsource", rpm:"iwd-debugsource~2.16~1.fc40", rls:"FC40"))) {
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
