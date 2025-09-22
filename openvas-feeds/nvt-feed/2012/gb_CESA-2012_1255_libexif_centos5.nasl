# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-September/018861.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881496");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-09-17 16:47:14 +0530 (Mon, 17 Sep 2012)");
  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836",
                "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2012:1255");
  script_name("CentOS Update for libexif CESA-2012:1255 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libexif'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libexif on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The libexif packages provide an Exchangeable image file format (Exif)
  library. Exif allows metadata to be added to and read from certain types
  of image files.

  Multiple flaws were found in the way libexif processed Exif tags. An
  attacker could create a specially-crafted image file that, when opened in
  an application linked against libexif, could cause the application to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running the application. (CVE-2012-2812, CVE-2012-2813, CVE-2012-2814,
  CVE-2012-2836, CVE-2012-2837, CVE-2012-2840, CVE-2012-2841)

  Red Hat would like to thank Dan Fandrich for reporting these issues.
  Upstream acknowledges Mateusz Jurczyk of the Google Security Team as the
  original reporter of CVE-2012-2812, CVE-2012-2813, and CVE-2012-2814, and
  Yunho Kim as the original reporter of CVE-2012-2836 and CVE-2012-2837.

  Users of libexif are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. All running
  applications linked against libexif must be restarted for the update to
  take effect.");
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

  if ((res = isrpmvuln(pkg:"libexif", rpm:"libexif~0.6.21~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexif-devel", rpm:"libexif-devel~0.6.21~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
