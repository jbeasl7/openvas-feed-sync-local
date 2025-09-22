# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.866050");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2013-07-08 10:32:07 +0530 (Mon, 08 Jul 2013)");
  script_cve_id("CVE-2013-1918", "CVE-2013-1432", "CVE-2013-2211", "CVE-2013-2194",
                "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-2076", "CVE-2013-2077",
                "CVE-2013-2078", "CVE-2013-2072", "CVE-2013-1952", "CVE-2013-1919",
                "CVE-2013-1917", "CVE-2013-1964", "CVE-2013-1920", "CVE-2013-0153",
                "CVE-2013-0215", "CVE-2012-6075", "CVE-2012-5634", "CVE-2012-5510",
                "CVE-2012-5511", "CVE-2012-5512", "CVE-2012-5513", "CVE-2012-5514",
                "CVE-2012-5515", "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537",
                "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-4544", "CVE-2012-4411",
                "CVE-2012-3494", "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3498",
                "CVE-2012-3515", "CVE-2012-3433", "CVE-2012-3432", "CVE-2012-0217",
                "CVE-2012-0218", "CVE-2012-2934", "CVE-2012-2625");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Update for xen FEDORA-2013-11871");
  script_xref(name:"FEDORA", value:"2013-11871");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-July/110866.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC17");
  script_tag(name:"affected", value:"xen on Fedora 17");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.5~9.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
