# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882494");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-18 05:19:33 +0200 (Wed, 18 May 2016)");
  script_cve_id("CVE-2016-3698");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-04 02:08:00 +0000 (Tue, 04 Oct 2016)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libndp CESA-2016:1086 centos7");
  script_tag(name:"summary", value:"Check the version of libndp");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Libndp is a library (used by NetworkManager)
that provides a wrapper for the IPv6 Neighbor Discovery Protocol. It also
provides a tool named ndptool for sending and receiving NDP messages.

Security Fix(es):

  * It was found that libndp did not properly validate and check the origin
of Neighbor Discovery Protocol (NDP) messages. An attacker on a non-local
network could use this flaw to advertise a node as a router, allowing them
to perform man-in-the-middle attacks on a connecting client, or disrupt the
network connectivity of that client. (CVE-2016-3698)

Red Hat would like to thank Julien Bernard (Viagenie) for reporting this
issue.");
  script_tag(name:"affected", value:"libndp on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:1086");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021893.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"libndp", rpm:"libndp~1.2~6.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libndp-devel", rpm:"libndp-devel~1.2~6.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
