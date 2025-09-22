# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-05/msg00021.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831409");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-03 09:20:26 +0200 (Fri, 03 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name:"MDVSA", value:"2011:095-1");
  script_cve_id("CVE-2011-0419", "CVE-2011-1928");
  script_name("Mandriva Update for apr MDVSA-2011:095-1 (apr)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apr'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2010\.0");
  script_tag(name:"affected", value:"apr on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64");
  script_tag(name:"insight", value:"It was discovered that the fix for CVE-2011-0419 under certain
  conditions could cause a denial-of-service (DoS) attack in APR
  (CVE-2011-1928).

  Packages for 2010.0 are provided as of the Extended Maintenance
  Program. The updated packages have been patched to correct this issue.

  Update:

  Packages for Mandriva Linux 2010.0 were missing with the MDVSA-2011:095
  advisory.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://store.mandriva.com/product_info.php?cPath=149&amp;amp;products_id=490");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"libapr1", rpm:"libapr1~1.3.9~1.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libapr-devel", rpm:"libapr-devel~1.3.9~1.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apr", rpm:"apr~1.3.9~1.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64apr1", rpm:"lib64apr1~1.3.9~1.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64apr-devel", rpm:"lib64apr-devel~1.3.9~1.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
