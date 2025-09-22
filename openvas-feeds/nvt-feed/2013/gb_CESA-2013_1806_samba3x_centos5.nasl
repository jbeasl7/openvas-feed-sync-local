# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881848");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-17 12:01:21 +0530 (Tue, 17 Dec 2013)");
  script_cve_id("CVE-2013-4408", "CVE-2013-4475");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for samba3x CESA-2013:1806 centos5");

  script_tag(name:"affected", value:"samba3x on CentOS 5");
  script_tag(name:"insight", value:"Samba is an open-source implementation of the Server Message Block (SMB) or
Common Internet File System (CIFS) protocol, which allows PC-compatible
machines to share files, printers, and other information.

A heap-based buffer overflow flaw was found in the DCE-RPC client code in
Samba. A specially crafted DCE-RPC packet could cause various Samba
programs to crash or, possibly, execute arbitrary code when parsed.
A malicious or compromised Active Directory Domain Controller could use
this flaw to compromise the winbindd daemon running with root privileges.
(CVE-2013-4408)

A flaw was found in the way Samba performed ACL checks on alternate file
and directory data streams. An attacker able to access a CIFS share with
alternate stream support enabled could access alternate data streams
regardless of the underlying file or directory ACL permissions.
(CVE-2013-4475)

Red Hat would like to thank the Samba project for reporting CVE-2013-4408.
Upstream acknowledges Stefan Metzmacher and Michael Adam of SerNet as the
original reporters of this issue.

All users of Samba are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, the smb service will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1806");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-December/020057.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba3x'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"samba3x", rpm:"samba3x~3.6.6~0.138.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-client", rpm:"samba3x-client~3.6.6~0.138.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-common", rpm:"samba3x-common~3.6.6~0.138.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-doc", rpm:"samba3x-doc~3.6.6~0.138.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-domainjoin-gui", rpm:"samba3x-domainjoin-gui~3.6.6~0.138.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-swat", rpm:"samba3x-swat~3.6.6~0.138.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-winbind", rpm:"samba3x-winbind~3.6.6~0.138.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba3x-winbind-devel", rpm:"samba3x-winbind-devel~3.6.6~0.138.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}