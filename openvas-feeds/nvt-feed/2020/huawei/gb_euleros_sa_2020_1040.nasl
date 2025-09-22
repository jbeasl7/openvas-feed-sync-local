# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1040");
  script_cve_id("CVE-2018-16852", "CVE-2018-16857", "CVE-2018-16860", "CVE-2019-10197", "CVE-2019-10218", "CVE-2019-14833", "CVE-2019-14847", "CVE-2019-14861", "CVE-2019-14870", "CVE-2019-3824");
  script_tag(name:"creation_date", value:"2020-01-23 13:17:07 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-18 16:12:24 +0000 (Wed, 18 Dec 2019)");

  script_name("Huawei EulerOS: Security Advisory for samba (EulerOS-SA-2020-1040)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.5\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1040");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1040");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'samba' package(s) announced via the EulerOS-SA-2020-1040 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Samba from version 4.9.0 and before version 4.9.3 that have AD DC configurations watching for bad passwords (to restrict brute forcing of passwords) in a window of more than 3 minutes may not watch for bad passwords at all. The primary risk from this issue is with regards to domains that have been upgraded from Samba 4.8 and earlier. In these cases the manual testing done to confirm an organisation's password policies apply as expected may not have been re-done after the upgrade.(CVE-2018-16857)

Samba from version 4.9.0 and before version 4.9.3 is vulnerable to a NULL pointer de-reference. During the processing of an DNS zone in the DNS management DCE/RPC server, the internal DNS server or the Samba DLZ plugin for BIND9, if the DSPROPERTY_ZONE_MASTER_SERVERS property or DSPROPERTY_ZONE_SCAVENGING_SERVERS property is set, the server will follow a NULL pointer and terminate. There is no further vulnerability associated with this issue, merely a denial of service.(CVE-2018-16852)

A flaw was found in samba versions 4.9.x up to 4.9.13, samba 4.10.x up to 4.10.8 and samba 4.11.x up to 4.11.0rc3, when certain parameters were set in the samba configuration file. An unauthenticated attacker could use this flaw to escape the shared directory and access the contents of directories outside the share.(CVE-2019-10197)

A flaw was found in samba 4.0.0 before samba 4.9.15 and samba 4.10.x before 4.10.10. An attacker can crash AD DC LDAP server via dirsync resulting in denial of service. Privilege escalation is not possible with this issue.(CVE-2019-14847)

A flaw was found in Samba, all versions starting samba 4.5.0 before samba 4.9.15, samba 4.10.10, samba 4.11.2, in the way it handles a user password change or a new password for a samba user. The Samba Active Directory Domain Controller can be configured to use a custom script to check for password complexity. This configuration can fail to verify password complexity when non-ASCII characters are used in the password, which could lead to weak passwords being set for samba users, making it vulnerable to dictionary attacks.(CVE-2019-14833)

A flaw was found in the samba client, all samba versions before samba 4.11.2, 4.10.10 and 4.9.15, where a malicious server can supply a pathname to the client with separators. This could allow the client to access files and folders outside of the SMB network pathnames. An attacker could use this vulnerability to create files outside of the current working directory using the privileges of the client user.(CVE-2019-10218)

A flaw was found in the way an LDAP search expression could crash the shared LDAP server process of a samba AD DC in samba before version 4.10. An authenticated user, having read permissions on the LDAP server, could use this flaw to cause denial of service.(CVE-2019-3824)

All Samba versions 4.x.x before 4.9.17, 4.10.x before 4.10.11 and 4.11.x before 4.11.3 have an issue, where ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'samba' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.5.0.");

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

if(release == "EULEROSVIRTARM64-3.0.5.0") {

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~4.9.1~2.h18.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient", rpm:"libwbclient~4.9.1~2.h18.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.9.1~2.h18.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.9.1~2.h18.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common-libs", rpm:"samba-common-libs~4.9.1~2.h18.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common-tools", rpm:"samba-common-tools~4.9.1~2.h18.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.9.1~2.h18.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
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
