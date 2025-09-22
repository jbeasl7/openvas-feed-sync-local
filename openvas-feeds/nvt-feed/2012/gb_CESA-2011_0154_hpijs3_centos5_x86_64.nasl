# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017345.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881287");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:18:41 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-4267");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2011:0154");
  script_name("CentOS Update for hpijs3 CESA-2011:0154 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hpijs3'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"hpijs3 on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Hewlett-Packard Linux Imaging and Printing (HPLIP) provides drivers for
  Hewlett-Packard printers and multifunction peripherals, and tools for
  installing, using, and configuring them.

  A flaw was found in the way certain HPLIP tools discovered devices using
  the SNMP protocol. If a user ran certain HPLIP tools that search for
  supported devices using SNMP, and a malicious user is able to send
  specially-crafted SNMP responses, it could cause those HPLIP tools to crash
  or, possibly, execute arbitrary code with the privileges of the user
  running them. (CVE-2010-4267)

  Red Hat would like to thank Sebastian Krahmer of the SuSE Security Team for
  reporting this issue.

  Users of hplip should upgrade to these updated packages, which contain a
  backported patch to correct this issue.");
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

  if ((res = isrpmvuln(pkg:"hpijs3", rpm:"hpijs3~3.9.8~11.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip3", rpm:"hplip3~3.9.8~11.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip3-common", rpm:"hplip3-common~3.9.8~11.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip3-gui", rpm:"hplip3-gui~3.9.8~11.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip3-libs", rpm:"hplip3-libs~3.9.8~11.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsane-hpaio3", rpm:"libsane-hpaio3~3.9.8~11.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
