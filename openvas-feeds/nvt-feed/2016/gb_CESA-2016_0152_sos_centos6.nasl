# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882390");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-11 06:41:04 +0100 (Thu, 11 Feb 2016)");
  script_cve_id("CVE-2015-7529");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 15:52:00 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for sos CESA-2016:0152 centos6");
  script_tag(name:"summary", value:"Check the version of sos");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The sos package contains a set of tools
that gather information from system hardware, logs and configuration files.
The information can then be used for diagnostic purposes and debugging.

An insecure temporary file use flaw was found in the way sos created
certain sosreport files. A local attacker could possibly use this flaw
to perform a symbolic link attack to reveal the contents of sosreport
files, or in some cases modify arbitrary files and escalate their
privileges on the system. (CVE-2015-7529)

This issue was discovered by Mateusz Guzik of Red Hat.

This update also fixes the following bug:

  * Previously, when the hpasm plug-in ran the 'hpasmcli' command in a Python
Popen constructor or a system pipeline, the command would hang and
eventually time out after 300 seconds. Sos was forced to wait for the time
out to finish, unnecessarily prolonging its run time. With this update, the
timeout of the 'hpasmcli' command has been set to 0, eliminating the delay
and speeding up sos completion time. (BZ#1291828)

All sos users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"affected", value:"sos on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:0152");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-February/021666.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"sos", rpm:"sos~3.2~28.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
