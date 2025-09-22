# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017472.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880532");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2011:0477");
  script_cve_id("CVE-2006-4192", "CVE-2011-1574");
  script_name("CentOS Update for gstreamer-plugins CESA-2011:0477 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"gstreamer-plugins on CentOS 4");
  script_tag(name:"insight", value:"The gstreamer-plugins packages contain plug-ins used by the GStreamer
  streaming-media framework to support a wide variety of media formats.

  An integer overflow flaw, leading to a heap-based buffer overflow, and a
  stack-based buffer overflow flaw were found in various ModPlug music file
  format library (libmodplug) modules, embedded in GStreamer. An attacker
  could create specially-crafted music files that, when played by a victim,
  would cause applications using GStreamer to crash or, potentially, execute
  arbitrary code. (CVE-2006-4192, CVE-2011-1574)

  All users of gstreamer-plugins are advised to upgrade to these updated
  packages, which contain backported patches to correct these issues. After
  installing the update, all applications using GStreamer (such as Rhythmbox)
  must be restarted for the changes to take effect.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"gstreamer-plugins", rpm:"gstreamer-plugins~0.8.5~1.EL.3", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-devel", rpm:"gstreamer-plugins-devel~0.8.5~1.EL.3", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
