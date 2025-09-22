# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882367");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-01-08 06:31:17 +0100 (Fri, 08 Jan 2016)");
  script_cve_id("CVE-2015-7236");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-07 14:04:00 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for rpcbind CESA-2016:0005 centos6");
  script_tag(name:"summary", value:"Check the version of rpcbind");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The rpcbind utility is a server that
converts RPC program numbers into universal addresses. It must be running on
the host to be able to make RPC calls on a server on that machine.

A use-after-free flaw related to the PMAP_CALLIT operation and TCP/UDP
connections was discovered in rpcbind. A remote attacker could possibly
exploit this flaw to crash the rpcbind service by performing a series of
UDP and TCP calls. (CVE-2015-7236)

All rpcbind users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. If the rpcbind service
is running, it will be automatically restarted after installing this
update.");
  script_tag(name:"affected", value:"rpcbind on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:0005");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-January/021593.html");
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

  if ((res = isrpmvuln(pkg:"rpcbind", rpm:"rpcbind~0.2.0~11.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
