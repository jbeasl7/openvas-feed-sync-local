# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882626");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-10 05:50:22 +0100 (Tue, 10 Jan 2017)");
  script_cve_id("CVE-2016-9445", "CVE-2016-9447", "CVE-2016-9809");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for gstreamer-plugins-bad-free CESA-2017:0018 centos7");
  script_tag(name:"summary", value:"Check the version of gstreamer-plugins-bad-free");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"GStreamer is a streaming media framework based
on graphs of filters which operate on media data. The gstreamer-plugins-bad-free
package contains a collection of plug-ins for GStreamer.

Security Fix(es):

  * An integer overflow flaw, leading to a heap-based buffer overflow, was
found in GStreamer's VMware VMnc video file format decoding plug-in. A
remote attacker could use this flaw to cause an application using GStreamer
to crash or, potentially, execute arbitrary code with the privileges of the
user running the application. (CVE-2016-9445)

  * A memory corruption flaw was found in GStreamer's Nintendo NSF music file
format decoding plug-in. A remote attacker could use this flaw to cause an
application using GStreamer to crash or, potentially, execute arbitrary
code with the privileges of the user running the application.
(CVE-2016-9447)

  * An out-of-bounds heap read flaw was found in GStreamer's H.264 parser. A
remote attacker could use this flaw to cause an application using GStreamer
to crash. (CVE-2016-9809)

Note: This update removes the vulnerable Nintendo NSF plug-in.");
  script_tag(name:"affected", value:"gstreamer-plugins-bad-free on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:0018");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-January/022196.html");
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

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-bad-free", rpm:"gstreamer-plugins-bad-free~0.10.23~22.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-bad-free-devel", rpm:"gstreamer-plugins-bad-free-devel~0.10.23~22.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-bad-free-devel-docs", rpm:"gstreamer-plugins-bad-free-devel-docs~0.10.23~22.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
