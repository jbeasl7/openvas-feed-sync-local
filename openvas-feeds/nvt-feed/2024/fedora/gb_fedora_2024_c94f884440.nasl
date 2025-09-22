# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.9994102884440");
  script_cve_id("CVE-2024-32487");
  script_tag(name:"creation_date", value:"2024-09-23 04:08:21 +0000 (Mon, 23 Sep 2024)");
  script_version("2024-09-23T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-09-23 05:05:44 +0000 (Mon, 23 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-c94f884440)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c94f884440");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-c94f884440");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274980");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274981");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'less' package(s) announced via the FEDORA-2024-c94f884440 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2024-32487 - less with LESSOPEN mishandles \n in paths");

  script_tag(name:"affected", value:"'less' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"less", rpm:"less~633~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"less-debuginfo", rpm:"less-debuginfo~633~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"less-debugsource", rpm:"less-debugsource~633~4.fc39", rls:"FC39"))) {
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
