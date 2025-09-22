# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882684");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-03-21 05:50:41 +0100 (Tue, 21 Mar 2017)");
  script_cve_id("CVE-2016-5139", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-7163",
                "CVE-2016-9675", "CVE-2013-6045");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-09 19:56:00 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for openjpeg CESA-2017:0559 centos6");
  script_tag(name:"summary", value:"Check the version of openjpeg");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenJPEG is an open source library for
reading and writing image files in JPEG2000 format.

Security Fix(es):

  * Multiple integer overflow flaws, leading to heap-based buffer overflows,
were found in OpenJPEG. A specially crafted JPEG2000 image could cause an
application using OpenJPEG to crash or, potentially, execute arbitrary
code. (CVE-2016-5139, CVE-2016-5158, CVE-2016-5159, CVE-2016-7163)

  * A vulnerability was found in the patch for CVE-2013-6045 for OpenJPEG. A
specially crafted JPEG2000 image, when read by an application using
OpenJPEG, could cause heap-based buffer overflows leading to a crash or,
potentially, arbitrary code execution. (CVE-2016-9675)

The CVE-2016-9675 issue was discovered by Doran Moppert (Red Hat Product
Security).");
  script_tag(name:"affected", value:"openjpeg on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:0559");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-March/022343.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"openjpeg", rpm:"openjpeg~1.3~16.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg-devel", rpm:"openjpeg-devel~1.3~16.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg-libs", rpm:"openjpeg-libs~1.3~16.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
