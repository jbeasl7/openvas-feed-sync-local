# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.867188");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2013-12-23 11:56:32 +0530 (Mon, 23 Dec 2013)");
  script_cve_id("CVE-2013-4920", "CVE-2013-4921", "CVE-2013-4922", "CVE-2013-4923",
                "CVE-2013-4924", "CVE-2013-4925", "CVE-2013-4926", "CVE-2013-4927",
                "CVE-2013-4074", "CVE-2013-4075", "CVE-2013-4076", "CVE-2013-4077",
                "CVE-2013-4078", "CVE-2013-4079", "CVE-2013-4080", "CVE-2013-4081",
                "CVE-2013-4082", "CVE-2013-4083", "CVE-2013-4928", "CVE-2013-4929",
                "CVE-2013-4930", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933",
                "CVE-2013-4934", "CVE-2013-4935", "CVE-2013-3559", "CVE-2013-3558",
                "CVE-2013-3557", "CVE-2013-3555", "CVE-2013-3562", "CVE-2013-3560");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Fedora Update for wireshark FEDORA-2013-17635");


  script_tag(name:"affected", value:"wireshark on Fedora 18");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"FEDORA", value:"2013-17635");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-December/124287.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC18");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.10.2~4.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
