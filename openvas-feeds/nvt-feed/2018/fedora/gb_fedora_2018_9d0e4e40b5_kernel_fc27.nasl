# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.874623");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-05-30 06:02:06 +0200 (Wed, 30 May 2018)");
  script_cve_id("CVE-2018-10840", "CVE-2018-3639", "CVE-2018-1120", "CVE-2018-10322",
                "CVE-2018-10323", "CVE-2018-1108", "CVE-2018-10021", "CVE-2017-18232",
                "CVE-2018-7995", "CVE-2018-8043", "CVE-2018-7757", "CVE-2018-5803",
                "CVE-2018-1065", "CVE-2018-1000026", "CVE-2018-5750", "CVE-2018-1000004",
                "CVE-2018-5344", "CVE-2018-5332", "CVE-2018-5333", "CVE-2017-17862",
                "CVE-2017-17863", "CVE-2017-17864", "CVE-2017-17852", "CVE-2017-17853",
                "CVE-2017-17854", "CVE-2017-17855", "CVE-2017-17856", "CVE-2017-17857",
                "CVE-2017-17741", "CVE-2017-17712", "CVE-2017-17449", "CVE-2017-17450",
                "CVE-2017-17448", "CVE-2017-17558", "CVE-2017-8824", "CVE-2017-1000405",
                "CVE-2017-16649", "CVE-2017-16650", "CVE-2017-16644", "CVE-2017-16647",
                "CVE-2017-15115", "CVE-2017-16532", "CVE-2017-16538", "CVE-2017-12193");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-07 02:14:00 +0000 (Fri, 07 Oct 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for kernel FEDORA-2018-9d0e4e40b5");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"affected", value:"kernel on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-9d0e4e40b5");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YAUGR47M3LDUN54S6SH2OQ3U6U2LS7HA");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.16.12~200.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
