# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.465102431009719");
  script_cve_id("CVE-2025-46397", "CVE-2025-46398", "CVE-2025-46399", "CVE-2025-46400");
  script_tag(name:"creation_date", value:"2025-07-23 04:18:16 +0000 (Wed, 23 Jul 2025)");
  script_version("2025-07-23T05:44:57+0000");
  script_tag(name:"last_modification", value:"2025-07-23 05:44:57 +0000 (Wed, 23 Jul 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-15 02:15:21 +0000 (Thu, 15 May 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-465f43da19)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-465f43da19");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-465f43da19");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2373186");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2373192");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2373195");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2373197");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'transfig' package(s) announced via the FEDORA-2025-465f43da19 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to latest upstream snapshot ee3f4d841d1ba7d5b1b57544c5068822ca92b1af");

  script_tag(name:"affected", value:"'transfig' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"transfig", rpm:"transfig~3.2.9a^20250619.ee3f4d8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"transfig-debuginfo", rpm:"transfig-debuginfo~3.2.9a^20250619.ee3f4d8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"transfig-debugsource", rpm:"transfig-debugsource~3.2.9a^20250619.ee3f4d8~1.fc41", rls:"FC41"))) {
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
