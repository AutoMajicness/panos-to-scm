## panos-to-scm
- **Migrate local PAN-OS firewall config into Strata Cloud Manager NGFW**
- **Migrate Panorama Device Group objects and policy into Strata Cloud Manager NGFW - legacy/in progress**
- **Migrate Cisco ASA/Firepower running config into Strata Cloud Manager - In progress**
- **Network stack migration currently targets local firewall XML only**

## Understand the following items before running
- **This script is as is, at your own risk, review license**
- **SCM supports "security profile groups" and not individual "security profiles" - make sure your policy reflects that**
- **SCM API doesn't fully support Antivirus/Wildfire API. Manually create this as it's treated as one profile. Script will reference "AntiVirus" profile from PANOS for security profile groups**
- **SCM API for security policies do not support adding schedules, if you have policies with schedules, manually add them to the policy**

### Step 1: Clone the Repository

```bash
git clone https://github.com/PaloAltoNetworks/panos-to-scm.git
cd panos-to-scm
```

### Step 2: Create a VENV and Install the Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Python 3.10 or newer is required.

### Step 3: SCM and PANOS Credentials
- **Common Services IAM account**
  - **Generate Service Account** Directions -> https://docs.paloaltonetworks.com/common-services/identity-and-access-access-management/manage-identity-and-access/add-service-accounts
- **SCM Credentials**: Interactive terminal runs prompt for Tenant ID, Client ID, and Client Secret for each customer run. Credentials are held in memory only and are not written to the PAN-API file. Use `--use-config` to reuse `$HOME/.panapi/config.yml`, or use the configured file automatically from non-interactive execution. Set `PANAPI_CONFIG` when using a different file.
  - **How to get there**:
  - **Window**s: `C:\users\<username>\.panapi\config.yml`
  - **MacOS**: `/Users/<username>/.panapi/config.yml`
  - **Linux**: `/home/<username>/.panapi/config.yml`

- Additionally add your PANOS NGFW/Panorama URL(make sure it ends in `/api/`) , Password and API Key
    - If you don't have API key for PANOS, the script will fetch API key and update config file
    - Optionally, you can ommit username/password and only apply the API key

```yaml
---
client_id: enter-username
client_secret: xxxxxxxxxxxxxxxxxxxxxx
tsg_id: enter-unique-tsg-here
palo_alto_ngfw_url: https://x.x.x.x/api/
palo_alto_password: service_account_password
palo_alto_username: service_account_name
palo_api_token: xxxxxxxxxxxxxxxxxxxxxx
```

### Step 4: Executing main.py for PAN-OS

For a per-customer interactive SCM run, start the script normally and enter the credentials when prompted:

```bash
python3 main.py \
  --target-folder Customer-FW \
  --object-scope folder:Customer-FW \
  --network-scope snippet:Customer-FW-network \
  --policy-scope folder:Customer-FW
```

The Tenant ID, Client ID, and Client Secret are used only for that process. Add `--use-config` when you intentionally want to use the credentials already stored in `PANAPI_CONFIG`.

For folder-first current-state collection, SCM resolves the folder's associated snippets automatically. This is the shortest As-Built data command:

```bash
python3 main.py \
  --snapshot-current-data \
  --snapshot-policy \
  --folder Customer-FW
```

Use `--resolve-folder Customer-FW` to inspect the associated snippets without collecting data. All snippets are fetched in SCM priority order; duplicate names use the higher-priority result and retain `_scm_scope` provenance. Explicit `--object-scope`, `--policy-scope`, `--network-scope`, or `--target-snippet` values override automatic resolution. Live network posting requires an explicit target snippet when a folder has multiple associated snippets.

Nested folders are resolved by their parent hierarchy. If a folder name is duplicated, an interactive run lists the full paths and asks you to choose one. For automation, use `--folder-path` or `--folder-id`:

```bash
python3 main.py \
  --snapshot-current-data \
  --snapshot-policy \
  --folder-path "CSM-PA440/PA-440/PA-440"
```

Nested snapshots include parent-folder policies and snippets by default and retain source-folder metadata. Use `--leaf-only` to collect only the selected folder. SCM configuration APIs scope objects and policies by folder name; if duplicate folders cannot be distinguished by the tenant's configuration endpoint, the script reports that limitation rather than silently selecting the wrong folder.

- If you run `main.py` as is, it'll ask if you want to fetch a new `running_config.xml` from your PANOS Endpoint
- If you want to use an offline XML file, then default XML file name must be in project directory and named `running_config.xml`
- Otherwise, it'll get the full running config from your PANOS device(controlled at $HOME/.panapi/config.yml)
- Script will Parse all XML and create dictionary of object types and security rules
- Script will GET all objects and rules from SCM and then compare your XML and post new entries.
  - There is some conflict resolution logic built in for same name objects that require user input.
  - Options are:
    - Merge - Useful for groups/lists
    - Replace - Replace the SCM value with XML Value
    - Append - Creates a new object with appended name `_new`. This is still work in progress, policies will still reference the original attribute
    - Ignore - Ignore the conflict and move on
- Also handles rule ordering if something gets out of order(order determined by XML) which occurs in parallel processing

### Recommended Local Firewall Workflow

Use dry-run first. Network configuration should normally target a snippet, while objects and policies usually target a folder. A local PAN-OS XML import with no selection flags defaults to the complete supported standalone configuration: objects, network configuration, security/decryption/application-override/NAT rules, and parsed dependencies. Live posting still requires the explicit `--post-objects`, `--post-network`, and `--post-policy` acknowledgements.

```bash
python3 main.py \
  --parser panos \
  --config-file running_config.xml \
  --panos-config-type local \
  --network-scope snippet:Network-Stack \
  --object-scope folder:All \
  --policy-scope folder:All \
  --dry-run \
  -o InterfaceManagementProfile,ZoneProtectionProfile,DHCPInterface,AggregateInterface,EthernetInterface,Layer2Subinterface,Layer3Subinterface,VlanInterface,TunnelInterface,LoopbackInterface,OSPFAuthProfile,BgpAuthProfile,BgpAddressFamilyProfile,BgpFilteringProfile,RoutePrefixList,RouteAccessList,RouteCommunityList,RoutePathAccessList,BgpRouteMap,BgpRouteMapRedistribution,BgpRedistributionProfile,LogicalRouter,IKECryptoProfile,IPsecCryptoProfile,IKEGateway,IPsecTunnel,PbfRule,Zones
```

The legacy `--scope folder:All` option still works as a fallback for all categories. Prefer the category-specific flags when network snippets and policy folders are different.

Object selection can be combined with policy flags. For example, `-o Address,Service --security-rules --nat-rules` parses and plans the selected object types plus the selected local firewall rulebases.

For standalone firewall imports, the live import path automatically checks the SCM migration target and creates the folder/snippet when either is missing. Supplying `--target-folder` and `--target-snippet` also supplies the corresponding object, policy, and network scopes when those scopes are omitted.

```bash
# Read-only check.
python3 main.py \
  --setup-scm-target \
  --target-folder FW1-GEJ \
  --target-snippet FW1-GEJ-network

# Explicitly create the missing setup objects.
python3 main.py \
  --setup-scm-target \
  --create-scm-target \
  --target-folder FW1-GEJ \
  --target-snippet FW1-GEJ-network \
  --parent-folder ngfw-shared
```

The command prints the follow-on scopes to use for migration: `folder:<target>` for objects/policies and `snippet:<target-network>` for network stack objects. SCM displays the NGFW root as All Firewalls, but the setup API parent value is `ngfw-shared`. The normal live import performs the same check/create operation immediately before posting; `--setup-scm-target` remains available when you want to provision the target without importing anything.

For CI-style local validation that does not require SCM authentication or scope prompts:

```bash
python3 main.py \
  --parser panos \
  --config-file running_config.xml \
  --panos-config-type local \
  --validate-only \
  --current-data current.json \
  -o InterfaceManagementProfile,ZoneProtectionProfile,DHCPInterface,AggregateInterface,EthernetInterface,Layer2Subinterface,Layer3Subinterface,VlanInterface,TunnelInterface,LoopbackInterface,OSPFAuthProfile,BgpAuthProfile,BgpAddressFamilyProfile,BgpFilteringProfile,RoutePrefixList,RouteAccessList,RouteCommunityList,RoutePathAccessList,BgpRouteMap,BgpRouteMapRedistribution,BgpRedistributionProfile,LogicalRouter,IKECryptoProfile,IPsecCryptoProfile,IKEGateway,IPsecTunnel,PbfRule,Zones
```

`--validate-only` prints the same planner summary plus a `blockers` count. It exits with status `1` when conflicts or unsupported parsed entries are present, and keeps schema-sensitive or missing-reference findings as warnings. Use `--strict-local-firewall` for local firewall imports to automatically promote missing network references, missing policy references, unsupported routing nodes, and unsupported local/Panorama layout warnings to validation blockers.

To fail validation on warnings, add `--warnings-as-errors`. To promote only specific warning classes, combine it with `--warning-codes`, for example:

```bash
python3 main.py \
  --parser panos \
  --config-file running_config.xml \
  --panos-config-type local \
  --validate-only \
  --strict-local-firewall
```

For a network-only offline report that does not require SCM scope/current-data comparison:

```bash
python3 main.py \
  --parser panos \
  --config-file running_config.xml \
  --panos-config-type local \
  --network-report \
  --report-output /tmp/network-report.json
```

For repeatable smoke checks against local real-world PAN-OS XML exports, use the sanitized smoke harness. It parses configs in local mode, builds dry-run validation summaries, and writes counts/warning summaries without raw object payloads:

```bash
python3 -m tools.smoke_real_configs \
  --config-dir /home/hawkinsd/As-Built_Document_Helper \
  --strict-local-firewall \
  --fail-on-blockers \
  --output /tmp/panos-to-scm-smoke.json
```

Use `--limit 1` for a quick parser smoke or repeat `--config-file path/to/config.xml` to target specific firewall exports.

### Command Line Options:
- Check the "HELP" feature using `python main.py -h`
- Run Specific Objects: `python main.py -o Tag,Address,AddressGroup`
  - You can run one, or multiple, comma seperated like above example
- Run Security Rules Only: `python main.py -s`
- Run App Override Rules Only: `python main.py -p`
- Run Decryption Rules Only: `python main.py -d`
- Run NAT Rules Only: `python main.py -n`
- Run All Objects, Security, App Override, Decryption and NAT Rules: `python main.py -a`
- Default Behavior: Running a local PAN-OS XML import without selection flags plans the full supported standalone configuration, including objects, network configuration, and policy/NAT rulebases. Use `-o` or individual rule flags to narrow the migration.
- Set a default SCM destination scope: `--scope folder:All`
- Set object/profile destination scope: `--object-scope folder:All`
- Set policy destination scope: `--policy-scope folder:All`
- Set network destination scope: `--network-scope snippet:Network-Stack`
- Build an offline plan without SCM authentication: `--dry-run`
- Run local parser/planner validation without SCM authentication or scope prompts: `--validate-only`
- Check/create target folder and network snippet without importing: `--setup-scm-target --create-scm-target --target-folder FW1 --target-snippet FW1-network`
- Let a live import provision missing target resources: `--target-folder FW1 --target-snippet FW1-network`
- Fetch current SCM object data into validation JSON: `--snapshot-current-data --snapshot-output /tmp/current-data.json`
- Fetch current SCM object, network, and policy rulebase data for As-Built documentation: `--snapshot-current-data --snapshot-policy --snapshot-output /tmp/current-data.json --object-scope folder:Customer-FW --network-scope snippet:Customer-FW-network --policy-scope folder:Customer-FW`
- Default generated artifacts are written to a customer folder in the current working directory. Use `--output-folder PATH` to override that location.
- Include common policy dependency object types in a snapshot: `--snapshot-policy-dependencies`
- Allow guarded live object/profile posting: `--post-objects`
- Allow guarded live policy/NAT posting: `--post-policy`
- Allow guarded live network object posting: `--post-network`
- Promote validate-only warnings to blockers: `--warnings-as-errors`
- Restrict promoted warnings by code: `--warning-codes missing-network-reference,unsupported-panos-routing-node`
- Promote recommended local firewall migration warnings to blockers: `--strict-local-firewall`
- Emit parsed network payloads and warnings without SCM comparison: `--network-report`
- Write a full dry-run plan: `--plan-output /tmp/plan.json`
- Write a full network report: `--report-output /tmp/network-report.json`
- Write grouped warning remediation without full payloads: `--remediation-output /tmp/remediation.json`
- Write an LLM-ready Markdown import report beside the source XML automatically after live import, for example `running_config.md`.
- Provide current SCM data for offline comparisons: `--current-data current.json`
- Review schema-sensitive and missing-reference network warnings in dry-run summary/output before posting generated routing payloads.

`--plan-output` includes a `posting_preview` section with dependency-ordered create/update batches by object type. Use this to review the order SCM posts would follow without exposing full payload details in the terminal summary. During live posting, the same flag writes a `live-post` validation bundle keyed by phase (`objects`, `network`, `policy`) so the exact pre-post validation inputs are preserved.

`--report-output` writes the network-only offline report when used with `--network-report`. During live posting, it writes a live migration report with validation summaries, final SCM snapshot counts for the selected object categories, rule-order verification results, and any SCM fetch failures that limited verification. Live XML imports also always write a Markdown report beside the source XML containing parsed counts, change lists, unsupported items, warning details, remediation actions, target scopes, and final SCM verification results for LLM-driven documentation or manual remediation.

`--current-data` expects a JSON object keyed by SCM object type name. Each value is a list of current tenant objects; at minimum, include `name` for reference validation, and include full payload fields when you want dry-run conflict comparison. A minimal network reference snapshot looks like:

```json
{
  "BgpRouteMap": [{"name": "tenant-existing-import-rm"}],
  "IKECryptoProfile": [{"name": "tenant-existing-ike-crypto"}],
  "IKEGateway": [{"name": "tenant-existing-vpn-gw"}],
  "IPsecCryptoProfile": [{"name": "tenant-existing-ipsec-crypto"}],
  "TunnelInterface": [{"name": "tunnel.1"}]
}
```

A committed sanitized example lives at `examples/current-data-network.json`.

To build that current-data file directly from SCM, authenticate normally and run a scoped snapshot:

```bash
python3 main.py \
  --snapshot-current-data \
  --snapshot-output /tmp/current-network.json \
  --network-scope snippet:Network-Stack \
  -o EthernetInterface,Layer3Subinterface,TunnelInterface,IKECryptoProfile,IPsecCryptoProfile,IKEGateway,IPsecTunnel,Zones,LogicalRouter
```

For policy validation, snapshot common dependency objects in one command:

```bash
python3 main.py \
  --snapshot-current-data \
  --snapshot-policy-dependencies \
  --snapshot-output /tmp/current-policy-dependencies.json \
  --object-scope folder:All \
  --network-scope snippet:Network-Stack
```

Use `--remediation-output /tmp/remediation.json` with `--validate-only`, `--dry-run`, or `--network-report` to write grouped warning actions with examples. This output is intended for review and ticketing; it omits full object payloads. During live posting, the same flag writes the validation remediation items grouped by phase so the remaining review work for a real import is captured alongside the live run.

Live posting is guarded by category. Selected object/profile types require `--post-objects`, selected policy/NAT rulebases require `--post-policy`, and selected network object types require `--post-network`; before posting, the tool builds a local plan and refuses to continue if validation blockers are present. Combine this with `--warnings-as-errors` and `--warning-codes` when you want missing references or parser warnings to stop posting.

Recommended live workflow:

```bash
# 1. Snapshot existing SCM dependencies.
python3 main.py \
  --snapshot-current-data \
  --snapshot-output /tmp/current-network.json \
  --network-scope snippet:Network-Stack \
  -o EthernetInterface,Layer3Subinterface,TunnelInterface,IKECryptoProfile,IPsecCryptoProfile,IKEGateway,IPsecTunnel,Zones,LogicalRouter

# 2. Validate the local firewall XML against generated payloads and current SCM data.
python3 main.py \
  --parser panos \
  --config-file running_config.xml \
  --panos-config-type local \
  --validate-only \
  --current-data /tmp/current-network.json \
  --strict-local-firewall \
  --remediation-output /tmp/remediation.json \
  -o InterfaceManagementProfile,ZoneProtectionProfile,DHCPInterface,AggregateInterface,EthernetInterface,Layer2Subinterface,Layer3Subinterface,VlanInterface,TunnelInterface,LoopbackInterface,IKECryptoProfile,IPsecCryptoProfile,IKEGateway,IPsecTunnel,Zones,LogicalRouter

# 3. Post only after validation is clean.
python3 main.py \
  --parser panos \
  --config-file running_config.xml \
  --panos-config-type local \
  --network-scope snippet:Network-Stack \
  --current-data /tmp/current-network.json \
  --strict-local-firewall \
  --post-network \
  --plan-output /tmp/live-network-plan.json \
  --remediation-output /tmp/live-network-remediation.json \
  --report-output /tmp/live-network-report.json \
  -o InterfaceManagementProfile,ZoneProtectionProfile,DHCPInterface,AggregateInterface,EthernetInterface,Layer2Subinterface,Layer3Subinterface,VlanInterface,TunnelInterface,LoopbackInterface,IKECryptoProfile,IPsecCryptoProfile,IKEGateway,IPsecTunnel,Zones,LogicalRouter
```

For full acceptance on a local firewall import, treat the live report as the proof artifact: validation summaries must show zero blockers, final snapshot counts should match the intended posted object types, and any `rule_order_verification` entries should show `verified: true`. Non-empty `fetch_failures` means SCM accepted the post but the tool could not fully prove final state for the affected endpoint.

### Currently Supported PAN-OS Migration Features:

- **External Dynamic List**
- **Custom URL Categories**
- **URL Filter Profiles**
- **Vulnerability Profiles**
- **Anti-Spyware Profiles**
- **DNS Security Profiles**
- **File Blocking Profiles**
- **Decryption Profiles**
- **Profile Groups**
- **Tags**
- **Address Objects**
- **Address Groups**
- **Service Objects**
- **Service Groups**
- **Applications**
- **Application Filters**
- **Application Groups**
- **HIP Objects**
- **HIP Profiles**
- **Security Rules**
- **NAT Rules**
- **Application Override Rules**
- **Decryption Policy Rules**

### Currently Supported Local PAN-OS Network Migration Features:

- **Interface Management Profiles**
- **Zone Protection Profiles**
- **DHCP Interfaces**
- **Aggregate Ethernet Interfaces**
- **Ethernet Interfaces**
- **Layer 2 Subinterfaces**
- **Layer 3 Subinterfaces**
- **VLAN Interfaces**
- **Tunnel Interfaces**
- **Loopback Interfaces**
- **OSPF Auth Profiles**
- **BGP Auth Profiles**
- **BGP Address Family Profiles**
- **BGP Filtering Profiles**
- **Route Prefix Lists from BGP Import/Export Policy Prefix Matches**
- **Route Access Lists from BGP Policy Access-List Matches**
- **Route Community Lists from BGP Policy Community Matches**
- **Route Path Access Lists from BGP Policy AS-Path Matches**
- **BGP Route Maps from BGP Import/Export Policy Rules**
- **BGP Route Map Redistributions**
- **BGP Redistribution Profiles**
- **Logical Routers with IPv4/IPv6 Static Routes**
- **Logical Router BGP Peer Groups and Peers**
- **Logical Router OSPF/OSPFv3 Areas and Interfaces**
- **IKE Crypto Profiles**
- **IPsec Crypto Profiles**
- **IKE Gateways**
- **IPsec Tunnels**
- **PBF Rules**
- **Security Zones**

Network features currently support local firewall XML and PAN-OS brace-format exports. Panorama templates and template stacks are not parsed yet.

DHCP client mode is supported for Layer 3 ethernet interfaces and Layer 3 ethernet subinterfaces. Static IP mode remains supported for ethernet, aggregate, subinterface, VLAN, tunnel, and loopback interfaces.

PAN-OS local firewall XML stores routes under `network/virtual-router`; this tool maps those source entries into SCM Logical Routers with `routing_stack` set to `advanced` for ARE-enabled firewalls. The parser also accepts PAN-OS brace-format exports that are sometimes saved with an `.xml` extension, such as `config { ... }` files. DHCP interface migration covers common local firewall DHCP server and relay interface settings. Logical router migration includes IPv4/IPv6 static routes, route-table options, passive static route options, BFD profile references, static route path-monitor data, BGP peer groups/peers with auth profile references, address-family profile references, filtering profile references, timers, multihop, and connection options, OSPF/OSPFv3 areas/interfaces with auth profile bindings, area ranges, virtual links, interface timing, and export rules, and BGP export route-map references under the Logical Router RIB filter.

Network object posting is dependency ordered even when `-o` is supplied out of order. The manager posts interfaces before DHCP/zones, route lists before route maps and filtering profiles, VPN crypto profiles before gateways/tunnels, and Logical Routers after their generated routing/VPN dependencies.

BGP import/export policy rules are converted into route-map objects and attached to migrated BGP peers under IPv4 or IPv6 unicast address-family data based on the matched prefix family. Route-map conversion includes prefix, access-list, community, AS-path, metric, local-preference, MED, next-hop, community, and AS-path set operations. Validate these payloads with `--dry-run` against real SCM current data before posting, because advanced routing schemas are strict and local PAN-OS XML can vary by PAN-OS release.

Dry-run plans include `warning_summary` counts grouped by warning code and object type, a `remediation` section with review actions and examples, plus a detailed `warnings` section for schema-sensitive or inferred network payloads, including generated BGP filtering profiles, BGP address-family profiles, Logical Router BGP peer references, static route option mappings, missing generated route-map/profile/list/VPN/interface references, missing security/NAT/decryption/application-override policy references, schedule references, and parser-reported unsupported PAN-OS routing nodes. Reference validation checks selected generated payloads against both parsed output and optional `--current-data`, which helps catch dependencies that were not selected with `-o` or that do not already exist in the target SCM tenant. Physical Ethernet references are matched against both SCM payload `name` values and `default_value` interface names, because generated Ethernet payload names use the SCM `$ethernet...` format while zones/routes reference PAN-OS interface names like `ethernet1/1`. These warnings are non-blocking unless promoted with `--warnings-as-errors`, `--warning-codes`, or `--strict-local-firewall`; use them as the review checklist before posting to SCM. Parser warnings are emitted under `_migration_warnings` in parsed data and are carried into dry-run plans automatically.

Sanitized local PAN-OS regression fixtures live under `tests/fixtures/panos/`. Add new fixtures there when validating XML variants from different PAN-OS releases, then cover the expected SCM payloads in focused test modules such as `tests/test_panos_routing_fixtures.py` and `tests/test_panos_policy_fixtures.py`. The fixture set includes focused BGP/OSPF/static-route variants, security/NAT/decryption policy reference variants, and a compact real-world edge-stack pattern with L3 interfaces, L3 subinterfaces, DHCP server/relay, tunnel interfaces, VPN objects, zones, and static route path monitoring. Current parser warnings include PAN-OS virtual-router ECMP, BGP dampening, BGP conditional advertisement, BGP graceful-restart routing options, unmapped BGP redistribution sources, multicast/PIM routing, static-route qualified-next-hop nodes, and Panorama template-style virtual-router layouts parsed in local mode.

Virtual-wire zone membership is parsed under security zones. Physical ethernet interfaces using virtual-wire mode are detected in the ethernet interface parser, but SCM currently exposes virtual-wire assignment differently than a standalone network object, so validate those dry-run payloads before posting.

## Cisco ASA/Firepower migration to SCM for PANOS
- Currently ASA/Firepower we need the running-config. `more system:running-config` or from FTD/FMC export the config. Must be in familiar ASA format
- Your cisco config must be in the project directory and named `cisco_config.txt`
- If you run `main.py` as is, it'll ask if you want to use the `cisco` or `panos` parser, type `cisco`
- Optionally, you can target specific object types such as `python main.py -o Address,AddressGroup`
- The script creates address objects in the form of:
  - N-address-CIDR for networks/ips that aren't objects in cisco config
- The script creates service objects in the form of:
  - There is a `map_port` method that handles terms such as `ssh, rsh, syslog, etc` and maps to port
  - This then creates object in format `TCP-22`
  - Additionally, service group objects with single members are treated as a "service" object
  - If another group references a `single member service group` it knows to reference the correct object
- Script will GET all objects and rules from SCM and then compare your `cisco_config.txt` and post new entries.
  - There is some conflict resolution logic built in for same name objects that require user input.
  - Options are:
    - Merge - Useful for groups/lists
    - Replace - Replace the SCM value with XML Value
    - Append - Creates a new object with appended name `_new`. This is still work in progress, policies will still reference the original attribute
    - Ignore - Ignore the conflict and move on
- Security Rules:
  - Supports ASA and Firepower L3/L4 Policies that reference service objects
  - If unsupported app/service (like icmp) it should tag rule for review
  - Currently destination zone is 'any' - route table lookup not implemented to determine dst zone
  - NAT rules are not considered, you will need to update Security policies with Pre-NAT IP Object


### Currently Supported Cisco ASA/Firepower Migration Features:
- **Address Objects**
- **Address Groups**
- **Service Objects**
- **Service Groups**
- **Security Rules**
