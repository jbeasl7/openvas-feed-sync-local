# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-April/015828.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880696");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0444");
  script_cve_id("CVE-2005-2974", "CVE-2005-3350");
  script_name("CentOS Update for giflib CESA-2009:0444 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'giflib'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"giflib on CentOS 5");
  script_tag(name:"insight", value:"The giflib packages contain a shared library of functions for loading and
  saving GIF image files. This library is API and ABI compatible with
  libungif, the library that supported uncompressed GIF image files while the
  Unisys LZW patent was in effect.

  Several flaws were discovered in the way giflib decodes GIF images. An
  attacker could create a carefully crafted GIF image that could cause an
  application using giflib to crash or, possibly, execute arbitrary code when
  opened by a victim. (CVE-2005-2974, CVE-2005-3350)

  All users of giflib are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. All running
  applications using giflib must be restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"giflib", rpm:"giflib~4.1.3~7.1.el5_3.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"giflib-devel", rpm:"giflib-devel~4.1.3~7.1.el5_3.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"giflib-utils", rpm:"giflib-utils~4.1.3~7.1.el5_3.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
