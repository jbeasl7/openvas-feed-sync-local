# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.874168");
  script_version("2023-06-28T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:22 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-02-28 08:40:13 +0100 (Wed, 28 Feb 2018)");
  script_cve_id("CVE-2017-9110", "CVE-2017-9111", "CVE-2017-9112", "CVE-2017-9113",
                "CVE-2017-9114", "CVE-2017-9115", "CVE-2017-9116", "CVE-2017-12596");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-30 22:15:00 +0000 (Sun, 30 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mingw-OpenEXR FEDORA-2018-b152c791cc");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-OpenEXR'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"mingw-OpenEXR on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"FEDORA", value:"2018-b152c791cc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DKXFNQWOBRDP6PAKF6GC7FKFZNQT3UOT");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC27");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"mingw32-OpenEXR", rpm:"mingw32-OpenEXR~2.2.0~7.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mingw64-OpenEXR", rpm:"mingw64-OpenEXR~2.2.0~7.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
