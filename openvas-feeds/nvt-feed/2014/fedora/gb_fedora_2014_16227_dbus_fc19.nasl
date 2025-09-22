# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.868618");
  script_version("2023-06-23T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-23 16:09:17 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2014-12-20 05:57:44 +0100 (Sat, 20 Dec 2014)");
  script_cve_id("CVE-2014-3635", "CVE-2014-3636", "CVE-2014-3637", "CVE-2014-3638",
                "CVE-2014-3639", "CVE-2014-7824", "CVE-2014-3477", "CVE-2014-3532",
                "CVE-2014-3533", "CVE-2013-2168");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for dbus FEDORA-2014-16227");
  script_tag(name:"summary", value:"Check the version of dbus");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"dbus on Fedora 19");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2014-16227");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-December/146403.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC19");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.6.28~1.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
