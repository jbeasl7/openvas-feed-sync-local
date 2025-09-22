# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807720");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2016-03-21 07:26:15 +0100 (Mon, 21 Mar 2016)");
  script_cve_id("CVE-2015-1120", "CVE-2015-1076", "CVE-2015-1071", "CVE-2015-1081",
                "CVE-2015-1122", "CVE-2015-1155", "CVE-2014-1748", "CVE-2015-3752",
                "CVE-2015-5809", "CVE-2015-5928", "CVE-2015-3749", "CVE-2015-3659",
                "CVE-2015-3748", "CVE-2015-3743", "CVE-2015-3731", "CVE-2015-3745",
                "CVE-2015-5822", "CVE-2015-3658", "CVE-2015-3741", "CVE-2015-3727",
                "CVE-2015-5801", "CVE-2015-5788", "CVE-2015-3747", "CVE-2015-5794",
                "CVE-2015-1127", "CVE-2015-1153", "CVE-2015-1083");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for webkitgtk3 FEDORA-2016-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkitgtk3'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"webkitgtk3 on Fedora 23");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2016-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-March/179133.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC23");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC23")
{

  if ((res = isrpmvuln(pkg:"webkitgtk3", rpm:"webkitgtk3~2.4.10~1.fc23", rls:"FC23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
