# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882991");
  script_version("2023-07-10T08:07:43+0000");
  script_cve_id("CVE-2018-19115");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-01-07 04:00:17 +0100 (Mon, 07 Jan 2019)");
  script_name("CentOS Update for keepalived CESA-2019:0022 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:0022");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-January/023140.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keepalived'
  package(s) announced via the CESA-2019:0022 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The keepalived utility provides simple and robust facilities for load
balancing and high availability. The load balancing framework relies on the
well-known and widely used IP Virtual Server (IPVS) kernel module providing
layer-4 (transport layer) load balancing. Keepalived implements a set of
checkers to dynamically and adaptively maintain and manage a load balanced
server pool according to the health of the servers. Keepalived also
implements the Virtual Router Redundancy Protocol (VRRPv2) to achieve high
availability with director failover.

Security Fix(es):

  * keepalived: Heap-based buffer overflow when parsing HTTP status codes
allows for denial of service or possibly arbitrary code execution
(CVE-2018-19115)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.");

  script_tag(name:"affected", value:"keepalived on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"keepalived", rpm:"keepalived~1.3.5~8.el7_6", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
