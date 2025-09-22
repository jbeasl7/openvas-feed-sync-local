# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140162");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-02-16 11:39:34 +0100 (Thu, 16 Feb 2017)");
  script_name("Cisco Smart Install (SMI) Protocol Misuse (cisco-sa-20170214-smi) - Unreliable Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_smi_tcp_detect.nasl");
  script_mandatory_keys("cisco/smi/detected");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170214-smi");
  script_xref(name:"URL", value:"https://blogs.cisco.com/security/cisco-psirt-mitigating-and-detecting-potential-abuse-of-cisco-smart-install-feature");
  script_xref(name:"URL", value:"https://blog.talosintelligence.com/cisco-coverage-for-smart-install-client/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210617044903/http://www.securityfocus.com/archive/1/540130");
  script_xref(name:"URL", value:"https://web.archive.org/web/20241215130153/https://2016.zeronights.ru/wp-content/uploads/2016/12/CiscoSmartInstall.v3.pdf");
  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/td/docs/switches/lan/smart_install/configuration/guide/smart_install/concepts.html#23355");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2018/04/16/russian-state-sponsored-cyber-actors-targeting-network-infrastructure-devices");

  script_tag(name:"summary", value:"Cisco is aware of a significant increase in Internet scans
  attempting to detect devices where, after completing setup, the Smart Install feature remains
  enabled and without proper security controls. This could leave the involved devices susceptible to
  misuse of the feature. Customers who have not done so are encouraged to follow guidance in the
  Recommendations section of this notice to assess and ensure their network switches are properly
  protected against abuse of the Smart Install feature.

  Several researchers have reported on the use of Smart Install (SMI) protocol messages toward Smart
  Install clients, also known as integrated branch clients (IBC), allowing an unauthenticated,
  remote attacker to change the startup-config file and force a reload of the device, load a new IOS
  image on the device, and execute high-privilege CLI commands on switches running Cisco IOS and IOS
  XE Software.

  Cisco does not consider this a vulnerability in Cisco IOS, IOS XE, or the Smart Install feature
  itself but a misuse of the Smart Install protocol, which does not require authentication by
  design. Customers who are seeking more than zero-touch deployment should consider deploying the
  Cisco Network Plug and Play solution instead.");

  script_tag(name:"vuldetect", value:"Checks if SMI is enabled on the remote host which indicates
  that the system might be affected.");

  script_tag(name:"solution", value:"Cisco has updated the Smart Install Configuration Guide to
  include security best practices regarding the deployment of the Cisco Smart Install feature within
  customer infrastructures.");

  # It seems we are not able to distinguish between Director and Client. As director is not
  # affected and mitigations might be in place use a lower QoD.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("port_service_func.inc");

if (!port = service_get_port(proto: "cisco_smi", nodefault: TRUE))
  exit(0);

report = "A service supporting the Cisco Smart Install (SMI) protocol was detected on the target host which might be affected.";
security_message(port: port, data: report);

exit(0);
