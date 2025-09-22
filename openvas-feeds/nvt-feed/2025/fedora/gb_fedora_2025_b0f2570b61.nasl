# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.98010225709861");
  script_cve_id("CVE-2025-4215");
  script_tag(name:"creation_date", value:"2025-05-28 04:06:45 +0000 (Wed, 28 May 2025)");
  script_version("2025-06-18T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-06-18 05:40:25 +0000 (Wed, 18 Jun 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-17 14:17:53 +0000 (Tue, 17 Jun 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-b0f2570b61)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b0f2570b61");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b0f2570b61");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2364052");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366177");
  script_xref(name:"URL", value:"https://github.com/gorhill/uBlock/releases/tag/1.64.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-ublock-origin' package(s) announced via the FEDORA-2025-b0f2570b61 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Latest upstream release. Changelog: [link moved to references] .

Fixes CVE-2025-4215 .");

  script_tag(name:"affected", value:"'mozilla-ublock-origin' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"mozilla-ublock-origin", rpm:"mozilla-ublock-origin~1.64.0~1.fc41", rls:"FC41"))) {
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
