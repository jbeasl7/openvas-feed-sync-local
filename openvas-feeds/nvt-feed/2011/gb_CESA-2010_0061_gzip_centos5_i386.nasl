# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-January/016475.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880616");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2010:0061");
  script_cve_id("CVE-2010-0001");
  script_name("CentOS Update for gzip CESA-2010:0061 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gzip'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"gzip on CentOS 5");
  script_tag(name:"insight", value:"The gzip package provides the GNU gzip data compression program.

  An integer underflow flaw, leading to an array index error, was found in
  the way gzip expanded archive files compressed with the Lempel-Ziv-Welch
  (LZW) compression algorithm. If a victim expanded a specially-crafted
  archive, it could cause gzip to crash or, potentially, execute arbitrary
  code with the privileges of the user running gzip. This flaw only affects
  64-bit systems. (CVE-2010-0001)

  Red Hat would like to thank Aki Helin of the Oulu University Secure
  Programming Group for responsibly reporting this flaw.

  Users of gzip should upgrade to this updated package, which contains a
  backported patch to correct this issue.");
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

  if ((res = isrpmvuln(pkg:"gzip", rpm:"gzip~1.3.5~11.el5.centos.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
