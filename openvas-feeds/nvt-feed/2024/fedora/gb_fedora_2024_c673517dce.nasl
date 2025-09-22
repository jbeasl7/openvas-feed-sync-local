# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886385");
  script_cve_id("CVE-2024-29131", "CVE-2024-29133");
  script_tag(name:"creation_date", value:"2024-04-03 01:16:06 +0000 (Wed, 03 Apr 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-c673517dce)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c673517dce");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-c673517dce");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2269294");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270548");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270673");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270674");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270689");
  script_xref(name:"URL", value:"https://github.com/apache/commons-configuration/blob/master/RELEASE-NOTES.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-commons-configuration' package(s) announced via the FEDORA-2024-c673517dce advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update contains security fixes for CVE-2024-29131 and CVE-2024-29133.

See [link moved to references] for changes in versions 2.10.0 and 2.10.1.");

  script_tag(name:"affected", value:"'apache-commons-configuration' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-configuration", rpm:"apache-commons-configuration~2.10.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-configuration-javadoc", rpm:"apache-commons-configuration-javadoc~2.10.1~1.fc40", rls:"FC40"))) {
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
