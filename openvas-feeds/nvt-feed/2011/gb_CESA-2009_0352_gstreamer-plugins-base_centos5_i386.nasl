# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-April/015741.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880852");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0352");
  script_cve_id("CVE-2009-0586");
  script_name("CentOS Update for gstreamer-plugins-base CESA-2009:0352 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-base'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"gstreamer-plugins-base on CentOS 5");
  script_tag(name:"insight", value:"GStreamer is a streaming media framework based on graphs of filters which
  operate on media data. GStreamer Base Plug-ins is a collection of
  well-maintained base plug-ins.

  An integer overflow flaw which caused a heap-based buffer overflow was
  discovered in the Vorbis comment tags reader. An attacker could create a
  carefully-crafted Vorbis file that would cause an application using
  GStreamer to crash or, potentially, execute arbitrary code if opened by a
  victim. (CVE-2009-0586)

  All users of gstreamer-plugins-base are advised to upgrade to these updated
  packages, which contain a backported patch to correct this issue. After
  installing this update, all applications using GStreamer (such as Totem or
  Rhythmbox) must be restarted for the changes to take effect.");
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

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-base", rpm:"gstreamer-plugins-base~0.10.20~3.0.1.el5_3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-base-devel", rpm:"gstreamer-plugins-base-devel~0.10.20~3.0.1.el5_3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
