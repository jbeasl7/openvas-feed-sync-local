# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2012-June/081681.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864273");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_version("2023-06-20T05:05:27+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:27 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"creation_date", value:"2012-06-04 11:05:59 +0530 (Mon, 04 Jun 2012)");
  script_cve_id("CVE-2012-2353", "CVE-2012-2354", "CVE-2012-2355", "CVE-2012-2356",
                "CVE-2012-2357", "CVE-2012-2358", "CVE-2012-2359", "CVE-2012-2360",
                "CVE-2012-2361", "CVE-2012-2362", "CVE-2012-2363", "CVE-2012-2364",
                "CVE-2012-2365", "CVE-2012-2366", "CVE-2012-2367");
  script_xref(name:"FEDORA", value:"2012-8325");
  script_name("Fedora Update for moodle FEDORA-2012-8325");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC16");
  script_tag(name:"affected", value:"moodle on Fedora 16");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.0.9~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
