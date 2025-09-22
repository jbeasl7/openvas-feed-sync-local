# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-July/016042.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880767");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1159");
  script_cve_id("CVE-2009-2285", "CVE-2009-2347");
  script_name("CentOS Update for libtiff CESA-2009:1159 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libtiff on CentOS 5");
  script_tag(name:"insight", value:"The libtiff packages contain a library of functions for manipulating Tagged
  Image File Format (TIFF) files.

  Several integer overflow flaws, leading to heap-based buffer overflows,
  were found in various libtiff color space conversion tools. An attacker
  could create a specially-crafted TIFF file, which once opened by an
  unsuspecting user, would cause the conversion tool to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the tool. (CVE-2009-2347)

  A buffer underwrite flaw was found in libtiff's Lempel-Ziv-Welch (LZW)
  compression algorithm decoder. An attacker could create a specially-crafted
  LZW-encoded TIFF file, which once opened by an unsuspecting user, would
  cause an application linked with libtiff to access an out-of-bounds memory
  location, leading to a denial of service (application crash).
  (CVE-2009-2285)

  The CVE-2009-2347 flaws were discovered by Tielei Wang from ICST-ERCIS,
  Peking University.

  All libtiff users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing this update,
  all applications linked with the libtiff library (such as Konqueror) must
  be restarted for the update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.8.2~7.el5_3.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~3.8.2~7.el5_3.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
