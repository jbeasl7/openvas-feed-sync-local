# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885177");
  script_tag(name:"creation_date", value:"2023-11-05 02:20:21 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-b659c62db9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-b659c62db9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-b659c62db9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188107");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188108");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2217253");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.93");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.94");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.95");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.96");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.97");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.98");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2023-004");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2023-005");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal7' package(s) announced via the FEDORA-2023-b659c62db9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- [7.98]([link moved to references])
- [7.97]([link moved to references])
- [7.96]([link moved to references])
 - [SA-CORE-2023-005]([link moved to references])
- [7.95]([link moved to references])
 - [SA-CORE-2023-004]([link moved to references])
- [7.94]([link moved to references])
- [7.93]([link moved to references])");

  script_tag(name:"affected", value:"'drupal7' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"drupal7", rpm:"drupal7~7.98~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal7-rpmbuild", rpm:"drupal7-rpmbuild~7.98~1.fc39", rls:"FC39"))) {
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
