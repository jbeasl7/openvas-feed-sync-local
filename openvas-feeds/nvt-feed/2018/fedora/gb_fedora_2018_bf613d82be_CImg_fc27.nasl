# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.875147");
  script_version("2023-06-28T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:22 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-10-06 08:41:16 +0200 (Sat, 06 Oct 2018)");
  script_cve_id("CVE-2018-7587", "CVE-2018-7588", "CVE-2018-7589", "CVE-2018-7637",
                "CVE-2018-7638", "CVE-2018-7639", "CVE-2018-7640", "CVE-2018-7641");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-26 23:15:00 +0000 (Wed, 26 Jun 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for CImg FEDORA-2018-bf613d82be");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'CImg'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"affected", value:"CImg on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-bf613d82be");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KEHLGQ4QGN56KLTUT4DN3KGSL7VJILW7");
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

  if ((res = isrpmvuln(pkg:"CImg", rpm:"CImg~2.3.6~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
