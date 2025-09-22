# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1556");
  script_cve_id("CVE-2014-9294", "CVE-2014-9750", "CVE-2015-5195", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7701", "CVE-2015-7703", "CVE-2015-7852", "CVE-2015-7974", "CVE-2015-7978", "CVE-2015-7979", "CVE-2016-2516", "CVE-2016-2518", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-7429", "CVE-2016-7433", "CVE-2016-9311", "CVE-2017-6463", "CVE-2018-12327");
  script_tag(name:"creation_date", value:"2020-01-23 12:14:17 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-10 16:57:49 +0000 (Fri, 10 Aug 2018)");

  script_name("Huawei EulerOS: Security Advisory for ntp (EulerOS-SA-2019-1556)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1556");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1556");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ntp' package(s) announced via the EulerOS-SA-2019-1556 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in the NTP server's parsing of configuration directives. A remote, authenticated attacker could cause ntpd to crash by sending a crafted message.(CVE-2017-6463)

ntpd in NTP 4.x before 4.2.8p8, when autokey is enabled, allows remote attackers to cause a denial of service (peer-variable clearing and association outage) by sending (1) a spoofed crypto-NAK packet or (2) a packet with an incorrect MAC value at a certain time.(CVE-2016-4955)

The ntpq and ntpdc command-line utilities that are part of ntp package are vulnerable to stack-based buffer overflow via crafted hostname. Applications using these vulnerable utilities with an untrusted input may be potentially exploited, resulting in a crash or arbitrary code execution under privileges of that application.(CVE-2018-12327)

NTP before 4.2.8p7 and 4.3.x before 4.3.92, when mode7 is enabled, allows remote attackers to cause a denial of service (ntpd abort) by using the same IP address multiple times in an unconfig directive.(CVE-2016-2516)

A flaw was found in the way NTP verified trusted keys during symmetric key authentication. An authenticated client (A) could use this flaw to modify a packet sent between a server (B) and a client (C) using a key that is different from the one known to the client (A).(CVE-2015-7974)

A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd was configured to use autokey authentication, an attacker could send packets to ntpd that would, after several days of ongoing attack, cause it to run out of memory.(CVE-2015-7701)

An out-of-bounds access flaw was found in the way ntpd processed certain packets. An authenticated attacker could use a crafted packet to create a peer association with hmode of 7 and larger, which could potentially (although highly unlikely) cause ntpd to crash.(CVE-2016-2518)

A stack-based buffer overflow was found in the way the NTP autokey protocol was implemented. When an NTP client decrypted a secret received from an NTP server, it could cause that client to crash.(CVE-2014-9750)

It was found that NTP's :config command could be used to set the pidfile and driftfile paths without any restrictions. A remote attacker could use this flaw to overwrite a file on the file system with a file containing the pid of the ntpd process (immediately) or the current estimated drift of the system clock (in hourly intervals).(CVE-2015-7703)

A flaw was found in the way ntpd running on a host with multiple network interfaces handled certain server responses. A remote attacker could use this flaw which would cause ntpd to not synchronize with the source.(CVE-2016-7429)

A flaw was found in the way ntpd implemented the trap service. A remote attacker could send a specially crafted packet to cause a null pointer dereference that will crash ntpd, resulting in a denial of service.(CVE-2016-9311)

It was found that ntp-keygen used a weak method for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ntp' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~28.h8", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~28.h8", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sntp", rpm:"sntp~4.2.6p5~28.h8", rls:"EULEROSVIRT-3.0.1.0"))) {
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
