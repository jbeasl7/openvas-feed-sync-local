# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.10079685100847");
  script_cve_id("CVE-2024-37890", "CVE-2024-48949");
  script_tag(name:"creation_date", value:"2024-10-24 04:08:58 +0000 (Thu, 24 Oct 2024)");
  script_version("2024-10-25T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-10-25 05:05:38 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 14:07:04 +0000 (Tue, 15 Oct 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-d79685d847)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-d79685d847");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-d79685d847");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303429");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317789");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yarnpkg' package(s) announced via the FEDORA-2024-d79685d847 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update bundled ws (CVE-2024-37890)

----

Update bundled dependencies to fix CVE-2024-48949.");

  script_tag(name:"affected", value:"'yarnpkg' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"yarnpkg", rpm:"yarnpkg~1.22.22~5.fc39", rls:"FC39"))) {
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
