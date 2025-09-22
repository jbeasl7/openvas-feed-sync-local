# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882319");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-05 06:16:48 +0100 (Thu, 05 Nov 2015)");
  script_cve_id("CVE-2015-4513", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193",
                "CVE-2015-7194", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2015:1982 centos6");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2015-4513, CVE-2015-7189, CVE-2015-7194, CVE-2015-7196,
CVE-2015-7198, CVE-2015-7197)

A same-origin policy bypass flaw was found in the way Firefox handled
certain cross-origin resource sharing (CORS) requests. A web page
containing malicious content could cause Firefox to disclose sensitive
information. (CVE-2015-7193)

A same-origin policy bypass flaw was found in the way Firefox handled URLs
containing IP addresses with white-space characters. This could lead to
cross-site scripting attacks. (CVE-2015-7188)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Christian Holler, David Major, Jesse Ruderman, Tyson
Smith, Boris Zbarsky, Randell Jesup, Olli Pettay, Karl Tomlinson, Jeff
Walden, and Gary Kwong, Micha Bentkowski, Looben Yang, Shinto K Anto,
Gustavo Grieco, Vytautas Staraitis, Ronald Crane, and Ehsan Akhgari as the
original reporters of these issues.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 38.4.0 ESR, which corrects these issues. After installing
the update, Firefox must be restarted for the changes to take effect.");
  script_tag(name:"affected", value:"firefox on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:1982");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-November/021471.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.4.0~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
