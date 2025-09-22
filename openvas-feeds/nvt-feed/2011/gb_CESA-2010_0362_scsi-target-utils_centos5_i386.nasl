# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-May/016657.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880662");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2010:0362");
  script_cve_id("CVE-2010-0743");
  script_name("CentOS Update for scsi-target-utils CESA-2010:0362 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'scsi-target-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"scsi-target-utils on CentOS 5");
  script_tag(name:"insight", value:"The scsi-target-utils package contains the daemon and tools to set up and
  monitor SCSI targets. Currently, iSCSI software and iSER targets are
  supported.

  A format string flaw was found in scsi-target-utils' tgtd daemon. A
  remote attacker could trigger this flaw by sending a carefully-crafted
  Internet Storage Name Service (iSNS) request, causing the tgtd daemon to
  crash. (CVE-2010-0743)

  All scsi-target-utils users should upgrade to this updated package, which
  contains a backported patch to correct this issue. All running
  scsi-target-utils services must be restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"scsi-target-utils", rpm:"scsi-target-utils~0.0~6.20091205snap.el5_5.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
