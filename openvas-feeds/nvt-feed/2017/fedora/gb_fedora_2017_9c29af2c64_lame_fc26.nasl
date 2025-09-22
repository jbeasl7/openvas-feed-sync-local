# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.873552");
  script_version("2023-06-22T13:00:03+0000");
  script_tag(name:"last_modification", value:"2023-06-22 13:00:03 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-11-02 18:05:28 +0530 (Thu, 02 Nov 2017)");
  script_cve_id("CVE-2015-9099", "CVE-2015-9100", "CVE-2017-11720", "CVE-2017-13712",
                "CVE-2017-15018", "CVE-2017-15019", "CVE-2017-15045", "CVE-2017-15046",
                "CVE-2017-9410", "CVE-2017-9411", "CVE-2017-9412", "CVE-2017-8419");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-31 01:29:00 +0000 (Thu, 31 Aug 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for lame FEDORA-2017-9c29af2c64");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'lame'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"lame on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2017-9c29af2c64");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Y4C44S3KMREUEPXI3KOGYZFGXUVVSHMV");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC26");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"lame", rpm:"lame~3.100~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
