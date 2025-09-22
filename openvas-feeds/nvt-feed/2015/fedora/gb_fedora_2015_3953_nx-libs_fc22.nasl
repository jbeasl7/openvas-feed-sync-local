# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.869710");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-07-07 06:37:31 +0200 (Tue, 07 Jul 2015)");
  script_cve_id("CVE-2011-2895", "CVE-2011-4028", "CVE-2013-4396", "CVE-2013-6462",
                "CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211", "CVE-2014-8092",
                "CVE-2014-8097", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8099",
                "CVE-2014-8100", "CVE-2014-8102", "CVE-2014-8101", "CVE-2014-8093",
                "CVE-2014-8098", "CVE-2015-0255");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for nx-libs FEDORA-2015-3953");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'nx-libs'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"nx-libs on Fedora 22");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2015-3953");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-March/152434.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC22");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"nx-libs", rpm:"nx-libs~3.5.0.29~1.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
