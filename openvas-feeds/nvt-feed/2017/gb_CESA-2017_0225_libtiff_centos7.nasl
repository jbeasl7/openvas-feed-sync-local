# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882647");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-03 12:11:05 +0530 (Fri, 03 Feb 2017)");
  script_cve_id("CVE-2015-8870", "CVE-2016-5652", "CVE-2016-9533", "CVE-2016-9534",
                "CVE-2016-9535", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9540");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libtiff CESA-2017:0225 centos7");
  script_tag(name:"summary", value:"Check the version of libtiff");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libtiff packages contain a library of
functions for manipulating Tagged Image File Format (TIFF) files.

Security Fix(es):

  * Multiple flaws have been discovered in libtiff. A remote attacker could
exploit these flaws to cause a crash or memory corruption and, possibly,
execute arbitrary code by tricking an application linked against libtiff
into processing specially crafted files. (CVE-2016-9533, CVE-2016-9534,
CVE-2016-9535)

  * Multiple flaws have been discovered in various libtiff tools (tiff2pdf,
tiffcrop, tiffcp, bmp2tiff). By tricking a user into processing a specially
crafted file, a remote attacker could exploit these flaws to cause a crash
or memory corruption and, possibly, execute arbitrary code with the
privileges of the user running the libtiff tool. (CVE-2015-8870,
CVE-2016-5652, CVE-2016-9540, CVE-2016-9537, CVE-2016-9536)");
  script_tag(name:"affected", value:"libtiff on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:0225");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-February/022261.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.3~27.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.3~27.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-static", rpm:"libtiff-static~4.0.3~27.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-tools", rpm:"libtiff-tools~4.0.3~27.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
