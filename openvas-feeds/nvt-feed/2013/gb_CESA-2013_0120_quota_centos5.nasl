# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019098.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881556");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-21 09:37:53 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2012-3417");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_xref(name:"CESA", value:"2013:0120");
  script_name("CentOS Update for quota CESA-2013:0120 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quota'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"quota on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The quota package provides system administration tools for monitoring
  and limiting user and group disk usage on file systems.

  It was discovered that the rpc.rquotad service did not use tcp_wrappers
  correctly. Certain hosts access rules defined in '/etc/hosts.allow' and
  '/etc/hosts.deny' may not have been honored, possibly allowing remote
  attackers to bypass intended access restrictions. (CVE-2012-3417)

  This issue was discovered by the Red Hat Security Response Team.

  This update also fixes the following bugs:

  * Prior to this update, values were not properly transported via the remote
  procedure call (RPC) and interpreted by the client when querying the quota
  usage or limits for network-mounted file systems if the quota values were
  2^32 kilobytes or greater. As a consequence, the client reported mangled
  values. This update modifies the underlying code so that such values are
  correctly interpreted by the client. (BZ#667360)

  * Prior to this update, warnquota sent messages about exceeded quota limits
  from a valid domain name if the warnquota tool was enabled to send warning
  e-mails and the superuser did not change the default warnquota
  configuration. As a consequence, the recipient could reply to invalid
  addresses. This update modifies the default warnquota configuration to use
  the reserved example.com. domain. Now, warnings about exceeded quota limits
  are sent from the reserved domain that inform the superuser to change to
  the correct value. (BZ#680429)

  * Previously, quota utilities could not recognize the file system as having
  quotas enabled and refused to operate on it due to incorrect updating of
  /etc/mtab. This update prefers /proc/mounts to get a list of file systems
  with enabled quotas. Now, quota utilities recognize file systems with
  enabled quotas as expected. (BZ#689822)

  * Prior to this update, the setquota(8) tool on XFS file systems failed
  to set disk limits to values greater than 2^31 kilobytes. This update
  modifies the integer conversion in the setquota(8) tool to use a 64-bit
  variable big enough to store such values. (BZ#831520)

  All users of quota are advised to upgrade to this updated package, which
  contains backported patches to resolve these issues.");
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

  if ((res = isrpmvuln(pkg:"quota", rpm:"quota~3.13~8.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
