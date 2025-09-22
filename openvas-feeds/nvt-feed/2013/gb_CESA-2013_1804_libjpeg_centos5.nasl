# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881844");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-17 12:00:02 +0530 (Tue, 17 Dec 2013)");
  script_cve_id("CVE-2013-6629");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for libjpeg CESA-2013:1804 centos5");

  script_tag(name:"affected", value:"libjpeg on CentOS 5");
  script_tag(name:"insight", value:"The libjpeg package contains a library of functions for manipulating JPEG
images. It also contains simple client programs for accessing the
libjpeg functions.

An uninitialized memory read issue was found in the way libjpeg decoded
images with missing Start Of Scan (SOS) JPEG markers. A remote attacker
could create a specially crafted JPEG image that, when decoded, could
possibly lead to a disclosure of potentially sensitive information.
(CVE-2013-6629)

All libjpeg users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1804");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-December/020053.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"libjpeg", rpm:"libjpeg~6b~38", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjpeg-devel", rpm:"libjpeg-devel~6b~38", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}