# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881912");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-03 11:31:04 +0530 (Thu, 03 Apr 2014)");
  script_cve_id("CVE-2012-5595", "CVE-2012-5598", "CVE-2012-5599", "CVE-2012-5600",
                "CVE-2012-6056", "CVE-2012-6060", "CVE-2012-6061", "CVE-2012-6062",
                "CVE-2013-3557", "CVE-2013-3559", "CVE-2013-4081", "CVE-2013-4083",
                "CVE-2013-4927", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933",
                "CVE-2013-4934", "CVE-2013-4935", "CVE-2013-5721", "CVE-2013-7112",
                "CVE-2014-2281", "CVE-2014-2299");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for wireshark CESA-2014:0341 centos5");

  script_tag(name:"affected", value:"wireshark on CentOS 5");
  script_tag(name:"insight", value:"Wireshark is a network protocol analyzer. It is used to
capture and browse the traffic running on a computer network.

Multiple flaws were found in Wireshark. If Wireshark read a malformed
packet off a network or opened a malicious dump file, it could crash or,
possibly, execute arbitrary code as the user running Wireshark.
(CVE-2013-3559, CVE-2013-4083, CVE-2014-2281, CVE-2014-2299)

Several denial of service flaws were found in Wireshark. Wireshark could
crash or stop responding if it read a malformed packet off a network, or
opened a malicious dump file. (CVE-2012-5595, CVE-2012-5598, CVE-2012-5599,
CVE-2012-5600, CVE-2012-6056, CVE-2012-6060, CVE-2012-6061, CVE-2012-6062,
CVE-2013-3557, CVE-2013-4081, CVE-2013-4927, CVE-2013-4931, CVE-2013-4932,
CVE-2013-4933, CVE-2013-4934, CVE-2013-4935, CVE-2013-5721, CVE-2013-7112)

All Wireshark users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running instances
of Wireshark must be restarted for the update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0341");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-March/020237.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.15~6.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.0.15~6.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
