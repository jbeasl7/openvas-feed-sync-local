# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122040");
  script_cve_id("CVE-2011-4083");
  script_tag(name:"creation_date", value:"2015-10-06 11:12:05 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2011-1536)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1536");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1536.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sos' package(s) announced via the ELSA-2011-1536 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.2-17.0.1.el6]
- Direct traceroute to linux.oracle.com (John Haxby) [orabug 11713272]
- Allow '-' in ticket (SR) numbers (John Haxby)
- Disable --upload option as it will not work with Oracle support
- Check oraclelinux-release instead of redhat-release to get OS version (John Haxby) [bug 11681869]
- Remove RH ftp URL and support email
- add sos-oracle-enterprise.patch

[2.2-17]
- Do not collect subscription manager keys in general plugin
Resolves: bz750607

[2.2-16]
- Fix execution of RHN hardware.py from hardware plugin
Resolves: bz736718
- Fix hardware plugin to support new lsusb path
Resolves: bz691477

[2.2-15]
- Fix brctl collection when a bridge contains no interfaces
 Resolves: bz697899
- Fix up2dateclient path in hardware plugin
 Resolves: bz736718

[2.2-14]
- Collect brctl show and showstp output
 Resolves: bz697899
- Collect nslcd.conf in ldap plugin
 Resolves: bz682124

[2.2-11]
- Truncate files that exceed specified size limit
 Resolves: bz683219
- Add support for collecting Red Hat Subscrition Manager configuration
 Resolves: bz714293
- Collect /etc/init on systems using upstart
 Resolves: bz694813
- Don't strip whitespace from output of external programs
 Resolves: bz713449
- Collect ipv6 neighbour table in network module
 Resolves: bz721163
- Collect basic cgroups configuration data
 Resolves: bz729455

[2.2-10]
- Fix collection of data from LVM2 reporting tools in devicemapper plugin
 Resolves: bz704383
- Add /proc/vmmemctl collection to vmware plugin
 Resolves: bz709491

[2.2-9]
- Collect yum repository list by default
 Resolves: bz600813
- Add basic Infiniband plugin
 Resolves: bz673244
- Add plugin for scsi-target-utils iSCSI target
 Resolves: bz677124
- Fix autofs plugin LC_ALL usage
 Resolves: bz683404
- Fix collection of lsusb and add collection of -t and -v outputs
 Resolves: bz691477
- Extend data collection by qpidd plugin
 Resolves: bz726360
- Add ethtool pause, coalesce and ring (-a, -c, -g) options to network plugin
 Resolves: bz726427");

  script_tag(name:"affected", value:"'sos' package(s) on Oracle Linux 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"sos", rpm:"sos~2.2~17.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
