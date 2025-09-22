# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-November/msg00010.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861520");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-27 16:01:32 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"FEDORA", value:"2007-2713");
  script_cve_id("CVE-2007-5623");
  script_name("Fedora Update for nagios-plugins FEDORA-2007-2713");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'nagios-plugins'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC7");
  script_tag(name:"affected", value:"nagios-plugins on Fedora 7");
  script_tag(name:"solution", value:"Please install the updated package(s).");
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

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"nagios-plugins", rpm:"nagios-plugins~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-udp", rpm:"nagios-plugins-udp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-linux_raid", rpm:"nagios-plugins-linux_raid~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ifoperstatus", rpm:"nagios-plugins-ifoperstatus~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ldap", rpm:"nagios-plugins-ldap~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ssh", rpm:"nagios-plugins-ssh~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ide_smart", rpm:"nagios-plugins-ide_smart~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-game", rpm:"nagios-plugins-game~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ntp", rpm:"nagios-plugins-ntp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-dummy", rpm:"nagios-plugins-dummy~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ircd", rpm:"nagios-plugins-ircd~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-perl", rpm:"nagios-plugins-perl~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-oracle", rpm:"nagios-plugins-oracle~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-disk", rpm:"nagios-plugins-disk~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-wave", rpm:"nagios-plugins-wave~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-time", rpm:"nagios-plugins-time~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-disk_smb", rpm:"nagios-plugins-disk_smb~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-mysql", rpm:"nagios-plugins-mysql~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-flexlm", rpm:"nagios-plugins-flexlm~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-dns", rpm:"nagios-plugins-dns~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-tcp", rpm:"nagios-plugins-tcp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-nagios", rpm:"nagios-plugins-nagios~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-mrtgtraf", rpm:"nagios-plugins-mrtgtraf~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-load", rpm:"nagios-plugins-load~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-breeze", rpm:"nagios-plugins-breeze~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-rpc", rpm:"nagios-plugins-rpc~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-dig", rpm:"nagios-plugins-dig~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-procs", rpm:"nagios-plugins-procs~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-by_ssh", rpm:"nagios-plugins-by_ssh~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-debuginfo", rpm:"nagios-plugins-debuginfo~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-mrtg", rpm:"nagios-plugins-mrtg~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-icmp", rpm:"nagios-plugins-icmp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-snmp", rpm:"nagios-plugins-snmp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-nwstat", rpm:"nagios-plugins-nwstat~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-apt", rpm:"nagios-plugins-apt~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-all", rpm:"nagios-plugins-all~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ups", rpm:"nagios-plugins-ups~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-nt", rpm:"nagios-plugins-nt~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-fping", rpm:"nagios-plugins-fping~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-swap", rpm:"nagios-plugins-swap~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-sensors", rpm:"nagios-plugins-sensors~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-log", rpm:"nagios-plugins-log~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-dhcp", rpm:"nagios-plugins-dhcp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins", rpm:"nagios-plugins~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ping", rpm:"nagios-plugins-ping~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ifstatus", rpm:"nagios-plugins-ifstatus~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-users", rpm:"nagios-plugins-users~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-radius", rpm:"nagios-plugins-radius~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-http", rpm:"nagios-plugins-http~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-mailq", rpm:"nagios-plugins-mailq~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-real", rpm:"nagios-plugins-real~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-smtp", rpm:"nagios-plugins-smtp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-pgsql", rpm:"nagios-plugins-pgsql~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-file_age", rpm:"nagios-plugins-file_age~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-hpjd", rpm:"nagios-plugins-hpjd~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-overcr", rpm:"nagios-plugins-overcr~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ntp", rpm:"nagios-plugins-ntp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-wave", rpm:"nagios-plugins-wave~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-file_age", rpm:"nagios-plugins-file_age~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ping", rpm:"nagios-plugins-ping~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-snmp", rpm:"nagios-plugins-snmp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-dig", rpm:"nagios-plugins-dig~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-users", rpm:"nagios-plugins-users~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-nagios", rpm:"nagios-plugins-nagios~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-linux_raid", rpm:"nagios-plugins-linux_raid~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-apt", rpm:"nagios-plugins-apt~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-dhcp", rpm:"nagios-plugins-dhcp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-radius", rpm:"nagios-plugins-radius~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-mysql", rpm:"nagios-plugins-mysql~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-flexlm", rpm:"nagios-plugins-flexlm~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-game", rpm:"nagios-plugins-game~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-nt", rpm:"nagios-plugins-nt~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-log", rpm:"nagios-plugins-log~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-udp", rpm:"nagios-plugins-udp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins", rpm:"nagios-plugins~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-load", rpm:"nagios-plugins-load~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-fping", rpm:"nagios-plugins-fping~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-http", rpm:"nagios-plugins-http~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-dummy", rpm:"nagios-plugins-dummy~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-disk_smb", rpm:"nagios-plugins-disk_smb~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ifoperstatus", rpm:"nagios-plugins-ifoperstatus~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-mailq", rpm:"nagios-plugins-mailq~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ifstatus", rpm:"nagios-plugins-ifstatus~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ups", rpm:"nagios-plugins-ups~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-smtp", rpm:"nagios-plugins-smtp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ldap", rpm:"nagios-plugins-ldap~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-dns", rpm:"nagios-plugins-dns~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-all", rpm:"nagios-plugins-all~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-overcr", rpm:"nagios-plugins-overcr~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-procs", rpm:"nagios-plugins-procs~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-rpc", rpm:"nagios-plugins-rpc~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-sensors", rpm:"nagios-plugins-sensors~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-breeze", rpm:"nagios-plugins-breeze~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-mrtgtraf", rpm:"nagios-plugins-mrtgtraf~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-debuginfo", rpm:"nagios-plugins-debuginfo~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-oracle", rpm:"nagios-plugins-oracle~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-swap", rpm:"nagios-plugins-swap~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ircd", rpm:"nagios-plugins-ircd~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-pgsql", rpm:"nagios-plugins-pgsql~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-time", rpm:"nagios-plugins-time~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-disk", rpm:"nagios-plugins-disk~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-icmp", rpm:"nagios-plugins-icmp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-hpjd", rpm:"nagios-plugins-hpjd~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-tcp", rpm:"nagios-plugins-tcp~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-real", rpm:"nagios-plugins-real~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-nwstat", rpm:"nagios-plugins-nwstat~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-perl", rpm:"nagios-plugins-perl~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-mrtg", rpm:"nagios-plugins-mrtg~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ide_smart", rpm:"nagios-plugins-ide_smart~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-ssh", rpm:"nagios-plugins-ssh~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nagios-plugins-by_ssh", rpm:"nagios-plugins-by_ssh~1.4.8~9.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}